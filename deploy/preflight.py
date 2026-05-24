#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         preflight.py
Description:  Pre-flight JSON Schema validation and configuration sanity checks.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

try:
    import jsonschema as _jsonschema
except ImportError:
    _jsonschema = None  # type: ignore[assignment]

from .constants import COPY_DIRS, COPY_FILES, SOURCE_DIR
from .log import _fatal, _info, _ok, _warn
from .utils import _load_toml

if TYPE_CHECKING:
    from .config import DeployConfig


def _resolve_agent_reference(cfg: "DeployConfig", raw_path: str) -> Path:
    """Resolve a path referenced from suricata-llm-agent.toml.

    Runtime config files are interpreted relative to the agent config file
    first, then relative to the deploy config directory, finally to the
    project source root for backward compatibility.
    """
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate

    search_order = [
        (cfg.agent_conf_path.parent / candidate).resolve(),
        (cfg._base_dir / candidate).resolve(),  # type: ignore[attr-defined]
        (SOURCE_DIR / candidate).resolve(),
    ]
    for resolved in search_order:
        if resolved.exists():
            return resolved
    return search_order[0]


def _validate_toml(data: dict, schema: dict, name: str) -> None:
    """Validate parsed TOML data against a JSON Schema.  Fatal on error."""
    if _jsonschema is None:
        return
    try:
        _jsonschema.validate(instance=data, schema=schema)
    except _jsonschema.ValidationError as e:
        path = (
            ".".join(str(p) for p in e.absolute_path)
            if e.absolute_path else "(root)"
        )
        _fatal(f"配置验证失败 [{name}]: {e.message}\n  位置: {path}")


def _validate_agent_memory_cross_constraints(agent_conf: dict) -> None:
    """Validate cross-field memory constraints not expressible in JSON Schema."""
    llm = agent_conf.get("llm", {})
    if not isinstance(llm, dict):
        return

    mode = str(llm.get("memory_mode", "pair")).lower()
    if mode not in ("proto_pair", "proto_pair_rolling"):
        return

    max_pairs = int(llm.get("memory_max_pairs", 50))
    evict = int(llm.get("memory_maxpair_lru_evict", 0))
    lat = float(llm.get("memory_lat_lru_evict_seconds", 3600.0))

    if max_pairs < 3:
        _fatal("proto_pair 模式要求 llm.memory_max_pairs >= 3")
    if lat <= 0:
        _fatal("proto_pair 模式要求 llm.memory_lat_lru_evict_seconds > 0")
    if evict != 0 and not (2 <= evict < max_pairs):
        _fatal(
            "proto_pair 模式要求 2 <= llm.memory_maxpair_lru_evict "
            "< llm.memory_max_pairs，或设置为 0 自动计算"
        )


def _extract_deploy_files(
    schema: dict, config: dict,
) -> list[tuple[str, str | None]]:
    """
    Recursively walk a JSON Schema and collect values from *config* for
    every property annotated with ``x-deploy-file: true``.

    Returns a list of ``(file_path_value, companion_schema_or_None)``.
    """
    results: list[tuple[str, str | None]] = []
    props = schema.get("properties", {})
    for key, prop_schema in props.items():
        if prop_schema.get("x-deploy-file") and key in config:
            value = config[key]
            if isinstance(value, str) and value.strip():
                companion = prop_schema.get("x-deploy-file-schema")
                results.append((value.strip(), companion))
        if prop_schema.get("type") == "object" and key in config:
            sub = config[key]
            if isinstance(sub, dict):
                results.extend(_extract_deploy_files(prop_schema, sub))
    return results


def _extract_deploy_dirs(
    schema: dict, config: dict,
) -> list[tuple[str, str | None]]:
    """
    Recursively walk a JSON Schema and collect values from *config* for
    every property annotated with ``x-deploy-dir: true``.

    Returns ``(dir_path, companion_schema_or_None)``.
    """
    results: list[tuple[str, str | None]] = []
    props = schema.get("properties", {})
    for key, prop_schema in props.items():
        if prop_schema.get("x-deploy-dir") and key in config:
            value = config[key]
            if isinstance(value, str) and value.strip():
                companion = prop_schema.get("x-deploy-dir-schema")
                results.append((value.strip(), companion))
        if prop_schema.get("type") == "object" and key in config:
            sub = config[key]
            if isinstance(sub, dict):
                results.extend(_extract_deploy_dirs(prop_schema, sub))
    return results


def _preflight_check(cfg: DeployConfig) -> tuple[list[str], list[str]]:
    """
    Validate all configuration files against their JSON Schemas and
    discover implicit deploy references via ``x-deploy-file`` /
    ``x-deploy-dir`` annotations in agent-config.schema.json.

    Returns ``(implicit_files, implicit_dirs)`` — paths not already in
    COPY_FILES / COPY_DIRS that must be added to the build context.
    """
    constraints_dir_name = cfg.deploy.get("general", {}).get(
        "constraints_dir", "constraints"
    )
    constraints_dir = cfg._cfg_dir / constraints_dir_name

    if not constraints_dir.is_dir():
        _warn(f"约束目录不存在，跳过预检: {constraints_dir}")
        return [], []

    if _jsonschema is None:
        _warn(
            "jsonschema 未安装，跳过 Schema 验证。"
            "执行 pip install jsonschema 以启用预检。"
        )
    else:
        _info("正在执行配置预检 ...")

    # ── Direct validations ───────────────────────────────────────────────
    validations: list[tuple[str, dict, str]] = [
        ("deploy-config.schema.json", cfg.deploy, "deploy.toml"),
        (
            "agent-config.schema.json",
            cfg.agent_conf,
            cfg.agent_conf_path.name,
        ),
        ("secrets.schema.json", cfg.secrets, "secrets.toml"),
        (
            "container-base.schema.json",
            cfg.container_base,
            f"container base ({cfg.deploy['container']['base']})",
        ),
        (
            "pm-config.schema.json",
            cfg.pm,
            f"package manager ({cfg.pm['pm_name']['pm_name']})",
        ),
    ]

    # Mail provider (only if a provider is configured)
    provider = cfg.agent_conf.get("mail", {}).get("provider", "").strip()
    if provider:
        provider_path = cfg._cfg_dir / "mail_providers" / f"{provider}.toml"
        if provider_path.is_file():
            validations.append((
                "mail-provider-config.schema.json",
                _load_toml(provider_path),
                f"mail provider ({provider})",
            ))

    for schema_file, data, name in validations:
        schema_path = constraints_dir / schema_file
        if not schema_path.is_file():
            _warn(f"Schema 不存在，跳过验证: {schema_file}")
            continue
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        _validate_toml(data, schema, name)

    _validate_agent_memory_cross_constraints(cfg.agent_conf)

    # ── Discover x-deploy-file / x-deploy-dir references ─────────────────
    agent_schema_path = constraints_dir / "agent-config.schema.json"
    if not agent_schema_path.is_file():
        if _jsonschema is not None:
            _ok("配置预检通过。")
        return [], []

    agent_schema = json.loads(
        agent_schema_path.read_text(encoding="utf-8")
    )
    deploy_file_refs = _extract_deploy_files(agent_schema, cfg.agent_conf)
    deploy_dir_refs = _extract_deploy_dirs(agent_schema, cfg.agent_conf)

    # Also extract x-deploy-file refs from deploy-config schema (e.g.
    # the agent config file itself).
    deploy_schema_path = constraints_dir / "deploy-config.schema.json"
    if deploy_schema_path.is_file():
        deploy_schema = json.loads(
            deploy_schema_path.read_text(encoding="utf-8")
        )
        deploy_file_refs.extend(
            _extract_deploy_files(deploy_schema, cfg.deploy)
        )

    # Validate referenced files that have companion schemas
    for file_value, ref_schema_file in deploy_file_refs:
        if not ref_schema_file:
            continue
        ref_schema_path = constraints_dir / ref_schema_file
        if not ref_schema_path.is_file():
            continue
        file_path = _resolve_agent_reference(cfg, file_value)
        if not file_path.is_file():
            continue  # existence checked later by _prepare_work_dir
        ref_data = _load_toml(file_path)
        ref_schema = json.loads(
            ref_schema_path.read_text(encoding="utf-8")
        )
        _validate_toml(ref_data, ref_schema, file_value)

    # Validate TOML files inside referenced directories with companion schemas
    for dir_value, dir_schema_file in deploy_dir_refs:
        if not dir_schema_file:
            continue
        dir_schema_path = constraints_dir / dir_schema_file
        if not dir_schema_path.is_file():
            continue
        dir_path = _resolve_agent_reference(cfg, dir_value)
        if not dir_path.is_dir():
            continue  # existence checked later by _prepare_work_dir
        dir_schema = json.loads(
            dir_schema_path.read_text(encoding="utf-8")
        )
        for toml_file in sorted(dir_path.glob("*.toml")):
            if toml_file.name == "examples.toml":
                continue  # reference template, not a real declaration
            toml_data = _load_toml(toml_file)
            _validate_toml(
                toml_data, dir_schema,
                str(toml_file),
            )

    if _jsonschema is not None:
        _ok("配置预检通过。")

    # ── Collect implicit deploy files ────────────────────────────────────
    copy_file_set = set(COPY_FILES)
    implicit_files: list[str] = []
    seen_f: set[str] = set()
    for file_value, _ in deploy_file_refs:
        basename = os.path.basename(file_value)
        if basename in copy_file_set or file_value in seen_f:
            continue
        seen_f.add(file_value)
        implicit_files.append(file_value)

    # ── Collect implicit deploy dirs ─────────────────────────────────────
    copy_dir_set = set(COPY_DIRS)
    implicit_dirs: list[str] = []
    seen_d: set[str] = set()
    for dir_value, _ in deploy_dir_refs:
        if dir_value in copy_dir_set or dir_value in seen_d:
            continue
        seen_d.add(dir_value)
        implicit_dirs.append(dir_value)

    return implicit_files, implicit_dirs
