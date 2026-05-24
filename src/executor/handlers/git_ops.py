#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         git_ops.py
Description:  Git operations and GitHub REST API handlers for issues, PRs, and commits.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from typing import Optional

import requests

from ...config import config
from ..models import ActionRequest, ActionStatus, ExecutionResult
from ..path_guard import check_write_path

logger = logging.getLogger(__name__)

# ── Helpers ──────────────────────────────────────────────────────────────────

def _github_headers() -> dict[str, str]:
    """Build authorization headers for GitHub API requests."""
    token = config.GIT_TOKEN
    if not token:
        raise RuntimeError("GIT_TOKEN is not configured.")
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _github_api_url(path: str) -> str:
    """Build full GitHub API URL from relative path."""
    base = config.GIT_API_BASE_URL.rstrip("/")
    return f"{base}{path}"


def _run_git(args: list[str], cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    """Execute a git command in the local repo directory."""
    repo_path = cwd or config.GIT_LOCAL_REPO_PATH
    env = os.environ.copy()
    # Suppress interactive prompts so commands fail fast on auth errors.
    env["GIT_TERMINAL_PROMPT"] = "0"
    result = subprocess.run(
        ["git"] + args,
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    return result


def _ensure_authenticated_remote() -> None:
    """Ensure the origin remote uses the token-embedded URL for push."""
    token = config.GIT_TOKEN
    remote_url = _effective_remote_url()
    if not token or not remote_url:
        return
    # Convert https://github.com/owner/repo.git to https://TOKEN@github.com/owner/repo.git
    if remote_url.startswith("https://") and "@" not in remote_url:
        auth_url = remote_url.replace("https://", f"https://x-access-token:{token}@", 1)
    else:
        auth_url = remote_url
    _run_git(["remote", "set-url", "origin", auth_url])


def _fork_mode() -> bool:
    """Return True when the agent operates on a fork repository."""
    return bool(config.GIT_FORK_OWNER)


def _fork_remote_url() -> str:
    """Build the HTTPS URL for the fork repository.

    Derives the URL from ``GIT_API_BASE_URL`` (to support GitHub Enterprise)
    combined with ``GIT_FORK_OWNER`` and ``GIT_REPO_NAME``.
    """
    # GIT_API_BASE_URL is e.g. "https://api.github.com" for github.com
    api_base = config.GIT_API_BASE_URL.rstrip("/")
    if "api.github.com" in api_base:
        host = "https://github.com"
    else:
        # GitHub Enterprise: https://git.example.com/api/v3 → https://git.example.com
        host = re.sub(r"/api/v\d+$", "", api_base)
    return f"{host}/{config.GIT_FORK_OWNER}/{config.GIT_REPO_NAME}.git"


def _upstream_remote_url() -> str:
    """Build the HTTPS URL for the upstream (original) repository."""
    if config.GIT_REMOTE_URL:
        return config.GIT_REMOTE_URL
    api_base = config.GIT_API_BASE_URL.rstrip("/")
    if "api.github.com" in api_base:
        host = "https://github.com"
    else:
        host = re.sub(r"/api/v\d+$", "", api_base)
    return f"{host}/{config.GIT_REPO_OWNER}/{config.GIT_REPO_NAME}.git"


def _effective_remote_url() -> str:
    """Return the URL that ``origin`` should point to.

    In fork mode this is the fork; otherwise the configured remote_url.
    """
    if _fork_mode():
        return _fork_remote_url()
    return config.GIT_REMOTE_URL


def _delete_conflicting_refs(branch: str) -> None:
    """Remove local branches whose ref paths conflict with *branch*.

    Git stores branch refs as filesystem entries under ``.git/refs/heads/``.
    A branch ``ai-rules`` is a *file* at ``refs/heads/ai-rules``, so creating
    ``ai-rules/20260326`` (which needs a *directory* ``refs/heads/ai-rules/``)
    will fail with ``cannot lock ref``.

    This helper detects two kinds of conflicts:

    1. **Prefix conflict** – an existing branch whose name is a prefix of
       *branch* (e.g. ``ai-rules`` blocks ``ai-rules/20260326``).
    2. **Child conflict** – an existing branch whose name has *branch* as a
       prefix (e.g. ``ai-rules/20260325`` blocks a hypothetical ``ai-rules``
       branch).

    Conflicting local branches are forcefully deleted so the target branch can
    be created cleanly.
    """
    parts = branch.split("/")
    branches_result = _run_git(["branch", "--list"])
    if branches_result.returncode != 0:
        return

    existing: set[str] = set()
    for line in branches_result.stdout.strip().splitlines():
        br = line.strip().removeprefix("* ").strip()
        if br:
            existing.add(br)

    # 1. Prefix conflict: any existing branch that is a strict prefix of
    #    *branch* and matches a complete path component.
    #    e.g. branch="ai-rules/20260326" → check "ai-rules"
    for i in range(1, len(parts)):
        prefix = "/".join(parts[:i])
        if prefix in existing:
            logger.info("Deleting conflicting prefix branch %r for target %r", prefix, branch)
            _run_git(["branch", "-D", prefix])

    # 2. Child conflict: any existing branch that starts with *branch* + "/"
    #    e.g. branch="ai-rules" → delete "ai-rules/20260325"
    child_prefix = branch + "/"
    for br in sorted(existing):
        if br.startswith(child_prefix):
            logger.info("Deleting conflicting child branch %r for target %r", br, branch)
            _run_git(["branch", "-D", br])


def _delete_conflicting_remote_refs(branch: str) -> None:
    """Remove **remote** branches whose ref paths conflict with *branch*.

    Same logic as :func:`_delete_conflicting_refs` but operates on the remote
    tracked by ``origin``.  Remote ref conflicts cause ``[remote rejected]``
    errors on push even when local refs have been cleaned up.
    """
    parts = branch.split("/")
    ls_result = _run_git(["ls-remote", "--heads", "origin"])
    if ls_result.returncode != 0:
        return

    remote_branches: set[str] = set()
    for line in ls_result.stdout.strip().splitlines():
        # Format: "<sha>\trefs/heads/<branch>"
        ref_part = line.split("\t", 1)
        if len(ref_part) == 2 and ref_part[1].startswith("refs/heads/"):
            remote_branches.add(ref_part[1].removeprefix("refs/heads/"))

    # 1. Prefix conflict on remote
    for i in range(1, len(parts)):
        prefix = "/".join(parts[:i])
        if prefix in remote_branches:
            logger.info(
                "Deleting conflicting remote prefix branch %r for target %r",
                prefix, branch,
            )
            _run_git(["push", "origin", "--delete", prefix])

    # 2. Child conflict on remote
    child_prefix = branch + "/"
    for br in sorted(remote_branches):
        if br.startswith(child_prefix):
            logger.info(
                "Deleting conflicting remote child branch %r for target %r",
                br, branch,
            )
            _run_git(["push", "origin", "--delete", br])


# ── Handler: create_github_issue ─────────────────────────────────────────────

def create_github_issue(request: ActionRequest) -> ExecutionResult:
    """Open a GitHub issue via the REST API."""
    title = request.params.get("title", "")
    body = request.params.get("body", "")
    labels_raw = request.params.get("labels", "")

    if not title:
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail="Missing required parameter: title",
        )

    owner = config.GIT_REPO_OWNER
    repo = config.GIT_REPO_NAME
    if not owner or not repo:
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail="git.repo_owner and git.repo_name must be configured.",
        )

    url = _github_api_url(f"/repos/{owner}/{repo}/issues")
    payload: dict = {"title": title, "body": body}
    if labels_raw:
        payload["labels"] = [l.strip() for l in labels_raw.split(",") if l.strip()]

    try:
        resp = requests.post(url, json=payload, headers=_github_headers(), timeout=30)
        resp.raise_for_status()
        data = resp.json()
        issue_number = data.get("number")
        issue_url = data.get("html_url", "")
        logger.info("Created GitHub issue #%s: %s", issue_number, issue_url)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.SUCCESS,
            detail=f"Issue #{issue_number} created.",
            output={"issue_number": issue_number, "url": issue_url},
        )
    except requests.HTTPError as exc:
        detail = f"GitHub API error: {exc.response.status_code} {exc.response.text[:200]}"
        logger.error("create_github_issue failed: %s", detail)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=detail,
        )
    except Exception as exc:
        logger.error("create_github_issue failed: %s", exc)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=str(exc),
        )


# ── Handler: create_github_pr ────────────────────────────────────────────────

def create_github_pr(request: ActionRequest) -> ExecutionResult:
    """Create a GitHub pull request via the REST API."""
    title = request.params.get("title", "")
    body = request.params.get("body", "")
    head = request.params.get("head_branch", "")
    base = request.params.get("base_branch", "") or config.GIT_DEFAULT_BRANCH

    if not title or not head:
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail="Missing required parameters: title, head_branch",
        )

    owner = config.GIT_REPO_OWNER
    repo = config.GIT_REPO_NAME
    if not owner or not repo:
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail="git.repo_owner and git.repo_name must be configured.",
        )

    url = _github_api_url(f"/repos/{owner}/{repo}/pulls")
    # In fork mode, GitHub requires "fork_owner:branch" for cross-repo PRs.
    if _fork_mode():
        head = f"{config.GIT_FORK_OWNER}:{head}"
    payload = {"title": title, "body": body, "head": head, "base": base}

    try:
        resp = requests.post(url, json=payload, headers=_github_headers(), timeout=30)
        resp.raise_for_status()
        data = resp.json()
        pr_number = data.get("number")
        pr_url = data.get("html_url", "")
        logger.info("Created GitHub PR #%s: %s", pr_number, pr_url)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.SUCCESS,
            detail=f"PR #{pr_number} created.",
            output={"pr_number": pr_number, "url": pr_url},
        )
    except requests.HTTPError as exc:
        detail = f"GitHub API error: {exc.response.status_code} {exc.response.text[:200]}"
        logger.error("create_github_pr failed: %s", detail)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=detail,
        )
    except Exception as exc:
        logger.error("create_github_pr failed: %s", exc)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=str(exc),
        )


# ── Handler: close_github_prs ────────────────────────────────────────────────

def close_github_prs(request: ActionRequest) -> ExecutionResult:
    """Close all open PRs from the fork against the upstream repository."""
    owner = config.GIT_REPO_OWNER
    repo = config.GIT_REPO_NAME
    fork_owner = config.GIT_FORK_OWNER

    if not owner or not repo:
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail="git.repo_owner and git.repo_name must be configured.",
        )
    if not fork_owner:
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail="git.fork_owner is not configured.",
        )

    try:
        # List open PRs whose head comes from the fork.
        list_url = _github_api_url(f"/repos/{owner}/{repo}/pulls")
        params = {
            "state": "open",
            "head": f"{fork_owner}:{config.GIT_DEFAULT_BRANCH}",
            "per_page": 100,
        }
        resp = requests.get(
            list_url, params=params, headers=_github_headers(), timeout=30,
        )
        resp.raise_for_status()
        open_prs = resp.json()

        if not open_prs:
            return ExecutionResult(
                request_id=request.request_id,
                capability=request.capability,
                status=ActionStatus.SUCCESS,
                detail="No open PRs from fork to close.",
            )

        closed: list[int] = []
        for pr in open_prs:
            pr_number = pr["number"]
            patch_url = _github_api_url(
                f"/repos/{owner}/{repo}/pulls/{pr_number}"
            )
            patch_resp = requests.patch(
                patch_url,
                json={"state": "closed"},
                headers=_github_headers(),
                timeout=30,
            )
            if patch_resp.ok:
                closed.append(pr_number)
                logger.info("Closed PR #%s", pr_number)
            else:
                logger.warning(
                    "Failed to close PR #%s: %s",
                    pr_number, patch_resp.text[:200],
                )

        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.SUCCESS,
            detail=f"Closed {len(closed)} PR(s): {closed}",
            output={"closed": closed},
        )
    except requests.HTTPError as exc:
        detail = f"GitHub API error: {exc.response.status_code} {exc.response.text[:200]}"
        logger.error("close_github_prs failed: %s", detail)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=detail,
        )
    except Exception as exc:
        logger.error("close_github_prs failed: %s", exc)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=str(exc),
        )


# ── Handler: git_commit_and_push ─────────────────────────────────────────────

def git_commit_and_push(request: ActionRequest) -> ExecutionResult:
    """Stage all changes, commit, and push to the remote branch."""
    message = request.params.get("commit_message", "")
    branch = request.params.get("branch", "")

    if not message:
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail="Missing required parameter: commit_message",
        )

    repo_path = config.GIT_LOCAL_REPO_PATH
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=f"Local repo not found at {repo_path}.",
        )

    # PathGuard: verify repo_path is within allowed write directories
    path_err = check_write_path(repo_path, request.resolved_write_dirs)
    if path_err:
        logger.warning("PathGuard denied git_commit_and_push: %s", path_err)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=f"PathGuard: {path_err}",
        )

    try:
        _ensure_authenticated_remote()

        # In fork mode we always work on the default branch — ignore
        # the branch parameter entirely so no feature branches are created.
        if _fork_mode():
            branch = ""

        # Create and switch to branch if specified
        if branch:
            # Delete conflicting refs that would prevent hierarchical branch
            # names like "ai-rules/20260326".  Git stores refs as a
            # file-system hierarchy under .git/refs/heads/, so a branch
            # "ai-rules" (a file) blocks "ai-rules/20260326" (needs a
            # directory) and vice-versa.
            _delete_conflicting_refs(branch)

            # Check if branch exists locally
            check = _run_git(["rev-parse", "--verify", branch])
            if check.returncode != 0:
                sw = _run_git(["checkout", "-b", branch])
            else:
                sw = _run_git(["checkout", branch])
            if sw.returncode != 0:
                return ExecutionResult(
                    request_id=request.request_id,
                    capability=request.capability,
                    status=ActionStatus.FAILED,
                    detail=f"git checkout failed: {sw.stderr}",
                )

        # Stage all changes
        result = _run_git(["add", "-A"])
        if result.returncode != 0:
            return ExecutionResult(
                request_id=request.request_id,
                capability=request.capability,
                status=ActionStatus.FAILED,
                detail=f"git add failed: {result.stderr}",
            )

        # Check if there are changes to commit
        status_result = _run_git(["status", "--porcelain"])
        if not status_result.stdout.strip():
            return ExecutionResult(
                request_id=request.request_id,
                capability=request.capability,
                status=ActionStatus.SUCCESS,
                detail="No changes to commit.",
            )

        # Commit
        result = _run_git(["commit", "-m", message,
                           "--author", "Suricata AI Agent <ai-agent@suricata-llm-agent.local>"])
        if result.returncode != 0:
            return ExecutionResult(
                request_id=request.request_id,
                capability=request.capability,
                status=ActionStatus.FAILED,
                detail=f"git commit failed: {result.stderr}",
            )

        # Push — use explicit refspec for branch names containing '/'
        if branch:
            # Delete remote refs that would conflict with the hierarchical
            # branch name (e.g. remote 'ai-rules' blocks 'ai-rules/20260327').
            _delete_conflicting_remote_refs(branch)
            push_target = f"HEAD:refs/heads/{branch}"
        else:
            push_target = "HEAD"
        result = _run_git(["push", "origin", push_target])
        if result.returncode != 0:
            return ExecutionResult(
                request_id=request.request_id,
                capability=request.capability,
                status=ActionStatus.FAILED,
                detail=f"git push failed: {result.stderr}",
            )

        logger.info("Committed and pushed to %s: %s", push_target, message[:80])
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.SUCCESS,
            detail=f"Pushed to {push_target}: {message[:80]}",
        )
    except Exception as exc:
        logger.error("git_commit_and_push failed: %s", exc)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=str(exc),
        )


# ── Handler: git_local_checkout_default ──────────────────────────────────────

def git_local_checkout_default(request: ActionRequest) -> ExecutionResult:
    """Switch local repo to default branch and discard uncommitted changes.

    Unlike ``git_repo_reset``, this does **not** fetch/pull from any remote
    and does **not** force-push.  It only affects the local working tree and
    is safe to call immediately after creating a PR without destroying the
    remote branch that backs it.
    """
    repo_path = config.GIT_LOCAL_REPO_PATH
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=f"Local repo not found at {repo_path}.",
        )

    path_err = check_write_path(repo_path, request.resolved_write_dirs)
    if path_err:
        logger.warning("PathGuard denied git_local_checkout_default: %s", path_err)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=f"PathGuard: {path_err}",
        )

    try:
        default_branch = config.GIT_DEFAULT_BRANCH
        _run_git(["checkout", default_branch])
        _run_git(["restore", "."])
        _run_git(["clean", "-fd"])

        logger.info("Local checkout to %s completed (no remote ops).", default_branch)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.SUCCESS,
            detail=f"Checked out {default_branch} and cleaned working tree.",
        )
    except Exception as exc:
        logger.error("git_local_checkout_default failed: %s", exc)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=str(exc),
        )


# ── Handler: git_repo_reset ──────────────────────────────────────────────────

def git_repo_reset(request: ActionRequest) -> ExecutionResult:
    """Discard all local changes and pull latest from remote."""
    repo_path = config.GIT_LOCAL_REPO_PATH
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=f"Local repo not found at {repo_path}.",
        )

    # PathGuard: verify repo_path is within allowed write directories
    path_err = check_write_path(repo_path, request.resolved_write_dirs)
    if path_err:
        logger.warning("PathGuard denied git_repo_reset: %s", path_err)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=f"PathGuard: {path_err}",
        )

    try:
        _ensure_authenticated_remote()
        default_branch = config.GIT_DEFAULT_BRANCH

        # Checkout default branch
        _run_git(["checkout", default_branch])

        # Discard all local changes
        _run_git(["restore", "."])
        _run_git(["clean", "-fd"])

        if _fork_mode():
            # Fork mode: sync local master with the upstream (original) repo,
            # then force-push to origin (the fork).  This effectively reverts
            # any un-merged PR changes on the fork.
            upstream_url = _upstream_remote_url()
            token = config.GIT_TOKEN
            if token and upstream_url.startswith("https://") and "@" not in upstream_url:
                auth_upstream = upstream_url.replace(
                    "https://", f"https://x-access-token:{token}@", 1,
                )
            else:
                auth_upstream = upstream_url

            # Ensure the upstream remote exists and points to the right URL.
            _run_git(["remote", "remove", "upstream"])  # ignore failure
            _run_git(["remote", "add", "upstream", auth_upstream])

            result = _run_git(["fetch", "upstream", default_branch])
            if result.returncode != 0:
                return ExecutionResult(
                    request_id=request.request_id,
                    capability=request.capability,
                    status=ActionStatus.FAILED,
                    detail=f"git fetch upstream failed: {result.stderr}",
                )

            _run_git(["reset", "--hard", f"upstream/{default_branch}"])

            result = _run_git(["push", "origin", default_branch, "--force"])
            if result.returncode != 0:
                return ExecutionResult(
                    request_id=request.request_id,
                    capability=request.capability,
                    status=ActionStatus.FAILED,
                    detail=f"git push --force to fork failed: {result.stderr}",
                )

            logger.info("Fork synced with upstream %s.", default_branch)
        else:
            # Same-repo mode: pull latest from origin.
            result = _run_git(["pull", "origin", default_branch])
            if result.returncode != 0:
                return ExecutionResult(
                    request_id=request.request_id,
                    capability=request.capability,
                    status=ActionStatus.FAILED,
                    detail=f"git pull failed: {result.stderr}",
                )

            # Delete local branches except default, and delete their remote
            # counterparts so that stale feature branches do not accumulate on
            # the remote (e.g. ai-rules/20260325, ai-rules/20260326 …).
            branches = _run_git(["branch", "--list"])
            if branches.returncode == 0:
                for line in branches.stdout.strip().splitlines():
                    br = line.strip().removeprefix("* ").strip()
                    if br and br != default_branch:
                        _run_git(["branch", "-D", br])
                        # Best-effort remote deletion — ignore failures
                        # (branch may not exist on remote or was already deleted).
                        del_result = _run_git(
                            ["push", "origin", "--delete", br]
                        )
                        if del_result.returncode == 0:
                            logger.info("Deleted remote branch: %s", br)
                        else:
                            logger.debug(
                                "Remote branch deletion skipped for %s: %s",
                                br, del_result.stderr.strip(),
                            )

        # Prune stale remote-tracking references
        _run_git(["remote", "prune", "origin"])

        # Compact refs to avoid stale loose ref files that cause
        # "cannot lock ref" errors with hierarchical branch names.
        _run_git(["pack-refs", "--all"])

        logger.info("Repository reset to %s and pulled latest.", default_branch)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.SUCCESS,
            detail=f"Reset to {default_branch} and pulled latest.",
        )
    except Exception as exc:
        logger.error("git_repo_reset failed: %s", exc)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=str(exc),
        )


# ── Handler: git_clone_repo ──────────────────────────────────────────────────

def git_clone_repo(request: ActionRequest) -> ExecutionResult:
    """Clone the configured remote repository to local_repo_path."""
    remote_url = _effective_remote_url()
    repo_path = config.GIT_LOCAL_REPO_PATH
    token = config.GIT_TOKEN

    if not remote_url:
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail="No remote URL resolved. Configure git.remote_url or git.fork_owner + git.repo_name.",
        )

    # Already cloned?
    if os.path.isdir(os.path.join(repo_path, ".git")):
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.SUCCESS,
            detail=f"Repository already exists at {repo_path}.",
        )

    # PathGuard: verify repo_path is within allowed write directories
    path_err = check_write_path(repo_path, request.resolved_write_dirs)
    if path_err:
        logger.warning("PathGuard denied git_clone_repo: %s", path_err)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=f"PathGuard: {path_err}",
        )

    # Build authenticated URL
    clone_url = remote_url
    if token and remote_url.startswith("https://") and "@" not in remote_url:
        clone_url = remote_url.replace("https://", f"https://x-access-token:{token}@", 1)

    try:
        os.makedirs(repo_path, exist_ok=True)
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        result = subprocess.run(
            ["git", "clone", clone_url, repo_path],
            capture_output=True, text=True, timeout=300, env=env,
        )
        if result.returncode != 0:
            return ExecutionResult(
                request_id=request.request_id,
                capability=request.capability,
                status=ActionStatus.FAILED,
                detail=f"git clone failed: {result.stderr}",
            )

        # Set authenticated remote URL (strip token from stored remote)
        _run_git(["remote", "set-url", "origin", remote_url])
        # Configure user for commits
        _run_git(["config", "user.name", "Suricata AI Agent"])
        _run_git(["config", "user.email", "ai-agent@suricata-llm-agent.local"])

        # In fork mode, add an 'upstream' remote pointing to the original repo.
        if _fork_mode():
            upstream_url = _upstream_remote_url()
            _run_git(["remote", "add", "upstream", upstream_url])
            logger.info("Added upstream remote: %s", upstream_url)

        logger.info("Cloned repository to %s.", repo_path)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.SUCCESS,
            detail=f"Cloned to {repo_path}.",
        )
    except Exception as exc:
        logger.error("git_clone_repo failed: %s", exc)
        return ExecutionResult(
            request_id=request.request_id,
            capability=request.capability,
            status=ActionStatus.FAILED,
            detail=str(exc),
        )
