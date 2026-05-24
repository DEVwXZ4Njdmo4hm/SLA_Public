#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         suricata_rules.py
Description:  Suricata rule suggestion handler with light and medium validation.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import tempfile
from typing import Optional

from ...config import config
from ..models import ActionRequest, ActionStatus, ExecutionResult
from ..path_guard import check_write_path

logger = logging.getLogger(__name__)

# ── Light validation ─────────────────────────────────────────────────────────
# Suricata rule structure:
#   action protocol src_addr src_port direction dst_addr dst_port (options)
# Example:
#   alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Test"; sid:1000001; rev:1;)

_RULE_RE = re.compile(
    r"^(alert|drop|pass|reject)\s+"    # action
    r"\S+\s+"                          # protocol
    r"\S+\s+"                          # src_addr
    r"\S+\s+"                          # src_port
    r"(->|<>)\s+"                      # direction
    r"\S+\s+"                          # dst_addr
    r"\S+\s+"                          # dst_port
    r"\(.*sid\s*:\s*\d+.*\)\s*$",      # options with sid
    re.DOTALL,
)

_SID_RE = re.compile(r"sid\s*:\s*(\d+)")

# ── Semantic validation helpers ──────────────────────────────────────────────

# Regex to decompose the rule header into named groups.
_HEADER_RE = re.compile(
    r"^(?P<action>alert|drop|pass|reject)\s+"
    r"(?P<proto>\S+)\s+"
    r"(?P<src_addr>\S+)\s+"
    r"(?P<src_port>\S+)\s+"
    r"(?:->|<>)\s+"
    r"(?P<dst_addr>\S+)\s+"
    r"(?P<dst_port>\S+)\s+"
    r"\((?P<options>.*)\)\s*$",
    re.DOTALL,
)

# Hardcoded private / loopback / link-local IPv4 literals (not variables).
_PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

# Null-byte-heavy content patterns that indicate fabricated payloads.
_NULL_CONTENT_RE = re.compile(r'\|(?:\s*00\s*){3,}\|')


def _semantic_validate(rule_text: str) -> Optional[str]:
    """Return an error if the rule has semantic issues, else None.

    Checks performed:
    1. Protocol / port coherence
    2. Hardcoded private IP addresses in header
    3. Fabricated all-zero content patterns
    4. flowbits:isset without paired set (standalone rule)
    5. Overly broad rules (no meaningful detection content)
    """
    single = " ".join(rule_text.strip().splitlines())
    m = _HEADER_RE.match(single)
    if not m:
        return None  # let light validation catch structural issues

    proto = m.group("proto").lower()
    src_addr = m.group("src_addr")
    dst_addr = m.group("dst_addr")
    src_port = m.group("src_port")
    dst_port = m.group("dst_port")
    options = m.group("options")
    options_lower = options.lower()

    # ── 1. Protocol / port coherence ─────────────────────────────────────
    # DNS detection should not run on port 80/443
    if "dns.query" in options_lower or "dns_query" in options_lower:
        for port in (src_port, dst_port):
            if port not in ("any", "53", "$DNS_SERVERS", "[53]"):
                if port.isdigit() and port != "53":
                    return (
                        f"Protocol/port mismatch: DNS detection keyword used "
                        f"but port is {port} instead of 53."
                    )

    # TLS sticky buffers on non-TLS ports
    tls_keywords = ("tls.sni", "tls_sni", "tls.cert_subject", "tls.ja3")
    if any(kw in options_lower for kw in tls_keywords):
        if proto not in ("tls", "tcp", "ip"):
            return (
                f"Protocol/port mismatch: TLS keyword used with protocol '{proto}'."
            )

    # ── 2. Hardcoded private IPs in header ───────────────────────────────
    for addr_field, label in ((src_addr, "source"), (dst_addr, "destination")):
        if _PRIVATE_IP_RE.search(addr_field):
            return (
                f"Hardcoded private IP in {label} address: '{addr_field}'. "
                f"Use $HOME_NET / $EXTERNAL_NET instead."
            )

    # ── 3. Fabricated all-zero content patterns ──────────────────────────
    if _NULL_CONTENT_RE.search(options):
        return (
            "Suspicious fabricated content pattern: sequences of null bytes "
            "(|00 00 00...|) rarely represent real threat signatures."
        )

    # ── 4. flowbits:isset without paired set ─────────────────────────────
    if "flowbits:isset," in options_lower or "flowbits: isset," in options_lower:
        if "flowbits:set," not in options_lower and "flowbits: set," not in options_lower:
            return (
                "Rule uses flowbits:isset without a corresponding flowbits:set "
                "in the same rule. Standalone rules with isset will never trigger."
            )

    # ── 5. Overly broad rules ────────────────────────────────────────────
    # A rule with no content/pcre/threshold/flowbits is essentially useless.
    has_content = "content:" in options_lower
    has_pcre = "pcre:" in options_lower
    has_threshold = "threshold:" in options_lower
    has_flowbits = "flowbits:" in options_lower
    has_detection_keyword = any(
        kw in options_lower
        for kw in ("dns.query", "tls.sni", "tls_sni", "http.uri",
                    "http.header", "ja3.hash", "ja3_hash", "file.data",
                    "byte_test:", "byte_jump:", "dsize:", "urilen:")
    )
    if not (has_content or has_pcre or has_threshold
            or has_flowbits or has_detection_keyword):
        return (
            "Rule lacks any detection logic (no content, pcre, threshold, "
            "flowbits, or protocol-specific keyword). It would match all traffic "
            "on the specified port."
        )

    return None


def _light_validate(rule_text: str) -> Optional[str]:
    """Return an error message if the rule fails light validation, else None."""
    rule_text = rule_text.strip()
    if not rule_text:
        return "Rule text is empty."
    # Allow multi-line rules by collapsing to one line
    single = " ".join(rule_text.splitlines())
    if not _RULE_RE.match(single):
        return (
            "Rule syntax does not match expected Suricata format. "
            "Expected: action proto src src_port -> dst dst_port (options with sid)"
        )
    # Check parentheses balance
    if single.count("(") != single.count(")"):
        return "Unbalanced parentheses in rule options."
    # Verify sid exists
    if not _SID_RE.search(single):
        return "Rule must contain a sid option."
    return None


def _medium_validate(rule_text: str) -> Optional[str]:
    """Return an error message if suricata -T rejects the rule, else None.

    Requires `suricata` binary to be available in PATH.
    """
    tmp_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, prefix="suri_validate_",
        ) as f:
            f.write(rule_text.strip() + "\n")
            tmp_path = f.name

        result = subprocess.run(
            ["suricata", "-T", "-S", tmp_path, "-l", "/tmp"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            # Extract meaningful error lines
            err_lines = []
            for line in (result.stderr + result.stdout).splitlines():
                lower = line.lower()
                if "error" in lower or "invalid" in lower or "failed" in lower:
                    err_lines.append(line.strip())
            detail = "; ".join(err_lines[:5]) if err_lines else "Suricata validation failed."
            return detail
        return None
    except FileNotFoundError:
        logger.warning("suricata binary not found; skipping medium validation.")
        return None
    except subprocess.TimeoutExpired:
        return "Suricata validation timed out."
    except Exception as exc:
        logger.warning("suricata -T failed unexpectedly: %s", exc)
        return None
    finally:
        try:
            if tmp_path:
                os.unlink(tmp_path)
        except Exception:
            pass


def _dedup_check(rule_text: str) -> Optional[str]:
    """Check if a rule with the same SID already exists in the rules directory.

    Returns an error message if a duplicate is found, else None.
    """
    repo_path = config.GIT_LOCAL_REPO_PATH
    rules_dir = os.path.join(repo_path, config.GIT_RULES_PATH)
    if not os.path.isdir(rules_dir):
        return None

    match = _SID_RE.search(rule_text)
    if not match:
        return None
    sid = match.group(1)

    for root, _dirs, files in os.walk(rules_dir):
        for fname in files:
            if not fname.endswith(".rules"):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    for line in f:
                        stripped = line.lstrip()
                        if stripped.startswith("#"):
                            continue
                        if _SID_RE.search(line) and f"sid:{sid}" in line.replace(" ", ""):
                            return f"Duplicate SID {sid} found in {fname}."
            except Exception:
                pass
    return None


# ── Handler ──────────────────────────────────────────────────────────────────

def suricata_rule_suggest(request: ActionRequest) -> ExecutionResult:
    """Validate a suggested Suricata rule and write it to the rules directory."""
    rule_text = request.params.get("rule_text", "").strip()
    priority = request.params.get("priority", 5)
    reference = request.params.get("reference", "")

    if not rule_text:
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail="Missing required parameter: rule_text",
        )

    # Light validation (always)
    err = _light_validate(rule_text)
    if err:
        logger.warning("Light validation failed for rule: %s", err)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=f"Light validation failed: {err}",
        )

    # Semantic validation (always – catches protocol/port mismatches, hardcoded
    # IPs, fabricated content, missing detection logic, etc.)
    err = _semantic_validate(rule_text)
    if err:
        logger.warning("Semantic validation failed for rule: %s", err)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=f"Semantic validation failed: {err}",
        )

    # Medium validation (optional, when configured and suricata is available)
    if config.GIT_VALIDATE_WITH_SURICATA:
        err = _medium_validate(rule_text)
        if err:
            logger.warning("Medium validation failed for rule: %s", err)
            return ExecutionResult(
                request_id=request.request_id,
                capability=request.capability,
                status=ActionStatus.FAILED,
                detail=f"Suricata validation failed: {err}",
            )

    # Dedup check
    err = _dedup_check(rule_text)
    if err:
        logger.info("Duplicate rule detected: %s", err)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=err,
        )

    # Write rule to the rules directory
    repo_path = config.GIT_LOCAL_REPO_PATH
    rules_dir = os.path.join(repo_path, config.GIT_RULES_PATH)

    try:
        os.makedirs(rules_dir, exist_ok=True)
    except OSError as exc:
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=f"Cannot create rules directory: {exc}",
        )

    # Generate a filename from the rule hash
    rule_hash = hashlib.sha256(rule_text.encode()).hexdigest()[:12]
    sid_match = _SID_RE.search(rule_text)
    sid = sid_match.group(1) if sid_match else "unknown"
    filename = f"ai_sid{sid}_{rule_hash}.rules"
    filepath = os.path.join(rules_dir, filename)

    # PathGuard: verify the computed write target is within allowed dirs
    path_err = check_write_path(filepath, request.resolved_write_dirs)
    if path_err:
        logger.warning("PathGuard denied rule write: %s", path_err)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=f"PathGuard: {path_err}",
        )

    try:
        header = f"# Auto-generated by Suricata AI Agent\n# Priority: {priority}\n"
        if reference:
            header += f"# Reference: {reference}\n"
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(header)
            f.write(rule_text.strip() + "\n")
    except OSError as exc:
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=f"Failed to write rule file: {exc}",
        )

    logger.info(
        "Suricata rule written: %s (sid=%s, priority=%s)",
        filename, sid, priority,
    )
    return ExecutionResult(
        request_id=request.request_id,
        capability=request.capability,
        status=ActionStatus.SUCCESS,
        detail=f"Rule written to {filename} (sid={sid}).",
        output={"filename": filename, "sid": sid, "filepath": filepath},
    )
