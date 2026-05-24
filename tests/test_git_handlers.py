#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_git_handlers.py
Description:  Tests for git operation and Suricata rule suggestion handlers.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import os
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
import requests

from src.executor.models import ActionRequest, ActionStatus, ExecutionResult
from src.executor.handlers.suricata_rules import (
    _light_validate,
    _medium_validate,
    _dedup_check,
    _semantic_validate,
    suricata_rule_suggest,
)
from src.executor.handlers.git_ops import (
    create_github_issue,
    create_github_pr,
    close_github_prs,
    git_commit_and_push,
    git_repo_reset,
    git_clone_repo,
    _delete_conflicting_refs,
    _delete_conflicting_remote_refs,
    _effective_remote_url,
    _fork_mode,
    _fork_remote_url,
    _upstream_remote_url,
)


# ═══════════════════════════════════════════════════════════════════════
# Light validation
# ═══════════════════════════════════════════════════════════════════════

class TestLightValidation:
    def test_valid_rule(self):
        rule = 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Test"; sid:1000001; rev:1;)'
        assert _light_validate(rule) is None

    def test_valid_drop_rule(self):
        rule = 'drop udp any any -> any 53 (msg:"Block DNS"; sid:2000001; rev:1;)'
        assert _light_validate(rule) is None

    def test_empty_rule(self):
        assert _light_validate("") is not None

    def test_whitespace_only(self):
        assert _light_validate("   ") is not None

    def test_missing_sid(self):
        rule = 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Test"; rev:1;)'
        assert _light_validate(rule) is not None

    def test_invalid_action(self):
        rule = 'block tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Test"; sid:1000001;)'
        assert _light_validate(rule) is not None

    def test_unbalanced_parens(self):
        rule = 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Test"; sid:1000001;'
        assert _light_validate(rule) is not None

    def test_bidirectional_rule(self):
        rule = 'alert tcp $HOME_NET any <> $EXTERNAL_NET 443 (msg:"Test"; sid:1000001; rev:1;)'
        assert _light_validate(rule) is None


# ═══════════════════════════════════════════════════════════════════════
# Medium validation
# ═══════════════════════════════════════════════════════════════════════

class TestMediumValidation:
    @patch("src.executor.handlers.suricata_rules.subprocess.run")
    def test_valid_rule_passes(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        result = _medium_validate('alert tcp any any -> any any (sid:999; rev:1;)')
        assert result is None

    @patch("src.executor.handlers.suricata_rules.subprocess.run")
    def test_invalid_rule_fails(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr="Error: invalid rule\n",
            stdout="",
        )
        result = _medium_validate('bad rule')
        assert result is not None

    @patch("src.executor.handlers.suricata_rules.subprocess.run",
           side_effect=FileNotFoundError)
    def test_suricata_not_found(self, _):
        result = _medium_validate('alert tcp any any -> any any (sid:999;)')
        assert result is None  # gracefully skip


# ═══════════════════════════════════════════════════════════════════════
# Semantic validation
# ═══════════════════════════════════════════════════════════════════════

class TestSemanticValidation:
    def test_valid_dns_rule(self):
        rule = (
            'alert dns $HOME_NET any -> any 53 '
            '(msg:"DNS query to .cc TLD"; dns.query; content:".cc"; endswith; '
            'threshold:type threshold, track by_src, seconds 60, count 15; '
            'classtype:bad-unknown; sid:9000101; rev:1;)'
        )
        assert _semantic_validate(rule) is None

    def test_valid_tls_rule(self):
        rule = (
            'alert tls $HOME_NET any -> $EXTERNAL_NET 443 '
            '(msg:"TLS SNI suspicious domain"; tls.sni; content:".duckdns.org"; endswith; '
            'classtype:trojan-activity; sid:9000103; rev:1;)'
        )
        assert _semantic_validate(rule) is None

    def test_valid_threshold_only_rule(self):
        rule = (
            'alert tcp $HOME_NET any -> $EXTERNAL_NET 8886 '
            '(msg:"Outbound to non-standard port"; flow:to_server,established; '
            'threshold:type threshold, track by_src, seconds 300, count 3; '
            'classtype:policy-violation; sid:9000102; rev:1;)'
        )
        assert _semantic_validate(rule) is None

    def test_dns_keyword_on_wrong_port(self):
        rule = (
            'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 '
            '(msg:"DNS on port 80"; dns.query; content:".cc"; '
            'sid:9000200; rev:1;)'
        )
        result = _semantic_validate(rule)
        assert result is not None
        assert "port" in result.lower()

    def test_hardcoded_private_ip_src(self):
        rule = (
            'alert tcp 192.168.24.175 any -> $EXTERNAL_NET 443 '
            '(msg:"test"; content:"malware"; sid:9000201; rev:1;)'
        )
        result = _semantic_validate(rule)
        assert result is not None
        assert "private IP" in result or "HOME_NET" in result

    def test_hardcoded_private_ip_dst(self):
        rule = (
            'alert tcp $HOME_NET any -> 10.0.0.1 443 '
            '(msg:"test"; content:"malware"; sid:9000202; rev:1;)'
        )
        result = _semantic_validate(rule)
        assert result is not None
        assert "private IP" in result

    def test_fabricated_null_content(self):
        rule = (
            'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 '
            '(msg:"test"; tls.sni; content:"|00 00 00 00|"; depth:4; '
            'sid:9000203; rev:1;)'
        )
        result = _semantic_validate(rule)
        assert result is not None
        assert "null" in result.lower() or "fabricated" in result.lower()

    def test_flowbits_isset_without_set(self):
        rule = (
            'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 '
            '(msg:"test"; flowbits:isset,proxy.bypass; '
            'classtype:policy-violation; sid:9000204; rev:1;)'
        )
        result = _semantic_validate(rule)
        assert result is not None
        assert "flowbits" in result.lower()

    def test_flowbits_isset_with_set_ok(self):
        rule = (
            'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 '
            '(msg:"test"; flowbits:set,test.flag; flowbits:isset,test.flag; '
            'content:"malware"; sid:9000205; rev:1;)'
        )
        assert _semantic_validate(rule) is None

    def test_overly_broad_rule(self):
        rule = (
            'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 '
            '(msg:"too broad"; flow:to_server; '
            'sid:9000206; rev:1;)'
        )
        result = _semantic_validate(rule)
        assert result is not None
        assert "detection" in result.lower() or "broad" in result.lower()

    def test_external_ip_in_header_ok(self):
        """External (non-private) IPs in header should pass."""
        rule = (
            'alert tcp $HOME_NET any -> 8.8.8.8 53 '
            '(msg:"test"; content:"malware"; sid:9000207; rev:1;)'
        )
        assert _semantic_validate(rule) is None

    def test_variables_in_header_ok(self):
        """Standard variables should always pass."""
        rule = (
            'alert tcp $HOME_NET any -> $EXTERNAL_NET any '
            '(msg:"test"; content:"malware"; sid:9000208; rev:1;)'
        )
        assert _semantic_validate(rule) is None


# ═══════════════════════════════════════════════════════════════════════
# Dedup check
# ═══════════════════════════════════════════════════════════════════════

class TestDedupCheck:
    def test_no_duplicate(self, tmp_path):
        rules_dir = tmp_path / "rules" / "ai"
        rules_dir.mkdir(parents=True)
        (rules_dir / "existing.rules").write_text(
            'alert tcp any any -> any any (sid:100; rev:1;)\n'
        )
        with patch("src.executor.handlers.suricata_rules.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_RULES_PATH = "rules/ai"
            result = _dedup_check('alert tcp any any -> any any (sid:200; rev:1;)')
        assert result is None

    def test_duplicate_found(self, tmp_path):
        rules_dir = tmp_path / "rules" / "ai"
        rules_dir.mkdir(parents=True)
        (rules_dir / "existing.rules").write_text(
            'alert tcp any any -> any any (sid:100; rev:1;)\n'
        )
        with patch("src.executor.handlers.suricata_rules.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_RULES_PATH = "rules/ai"
            result = _dedup_check('alert tcp any any -> any any (sid:100; rev:1;)')
        assert result is not None
        assert "100" in result

    def test_no_rules_dir(self, tmp_path):
        with patch("src.executor.handlers.suricata_rules.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_RULES_PATH = "rules/ai"
            result = _dedup_check('alert tcp any any -> any any (sid:300;)')
        assert result is None


# ═══════════════════════════════════════════════════════════════════════
# suricata_rule_suggest handler
# ═══════════════════════════════════════════════════════════════════════

class TestSuricataRuleSuggestHandler:
    def test_missing_rule_text(self):
        req = ActionRequest(capability="suricata_rule_suggest", params={})
        result = suricata_rule_suggest(req)
        assert result.status == ActionStatus.FAILED
        assert "rule_text" in result.detail

    def test_light_validation_failure(self):
        req = ActionRequest(
            capability="suricata_rule_suggest",
            params={"rule_text": "not a valid rule"},
        )
        result = suricata_rule_suggest(req)
        assert result.status == ActionStatus.FAILED
        assert "Light validation" in result.detail

    def test_success_write(self, tmp_path):
        rule = (
            'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 '
            '(msg:"Test rule"; content:"malware"; sid:9999; rev:1;)'
        )
        req = ActionRequest(
            capability="suricata_rule_suggest",
            params={"rule_text": rule, "priority": 3},
            resolved_write_dirs=[str(tmp_path)],
        )
        with patch("src.executor.handlers.suricata_rules.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_RULES_PATH = "rules/ai"
            mock_cfg.GIT_VALIDATE_WITH_SURICATA = False
            result = suricata_rule_suggest(req)

        assert result.status == ActionStatus.SUCCESS
        assert "9999" in result.detail
        # Verify rule file was written
        rules_dir = tmp_path / "rules" / "ai"
        rule_files = list(rules_dir.glob("ai_sid9999_*.rules"))
        assert len(rule_files) == 1
        content = rule_files[0].read_text()
        assert "sid:9999" in content
        assert "Priority: 3" in content


# ═══════════════════════════════════════════════════════════════════════
# create_github_issue handler
# ═══════════════════════════════════════════════════════════════════════

class TestCreateGitHubIssue:
    def test_missing_title(self):
        req = ActionRequest(
            capability="create_github_issue",
            params={"body": "some body"},
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = ""
            result = create_github_issue(req)
        assert result.status == ActionStatus.FAILED
        assert "title" in result.detail

    def test_missing_repo_config(self):
        req = ActionRequest(
            capability="create_github_issue",
            params={"title": "Test issue"},
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REPO_OWNER = ""
            mock_cfg.GIT_REPO_NAME = ""
            result = create_github_issue(req)
        assert result.status == ActionStatus.FAILED

    @patch("src.executor.handlers.git_ops.requests.post")
    def test_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"number": 42, "html_url": "https://github.com/test/42"}
        mock_post.return_value = mock_resp

        req = ActionRequest(
            capability="create_github_issue",
            params={"title": "Test", "body": "Body", "labels": "bug,ai"},
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REPO_OWNER = "test-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            result = create_github_issue(req)

        assert result.status == ActionStatus.SUCCESS
        assert result.output["issue_number"] == 42


# ═══════════════════════════════════════════════════════════════════════
# create_github_pr handler
# ═══════════════════════════════════════════════════════════════════════

class TestCreateGitHubPr:
    def test_missing_params(self):
        req = ActionRequest(
            capability="create_github_pr",
            params={"title": "PR"},
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = ""
            result = create_github_pr(req)
        assert result.status == ActionStatus.FAILED
        assert "head_branch" in result.detail

    @patch("src.executor.handlers.git_ops.requests.post")
    def test_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"number": 10, "html_url": "https://github.com/test/pull/10"}
        mock_post.return_value = mock_resp

        req = ActionRequest(
            capability="create_github_pr",
            params={
                "title": "AI Rules",
                "body": "Test body",
                "head_branch": "ai-rules/20260301",
                "base_branch": "main",
            },
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REPO_OWNER = "test-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            result = create_github_pr(req)

        assert result.status == ActionStatus.SUCCESS
        assert result.output["pr_number"] == 10


# ═══════════════════════════════════════════════════════════════════════
# git_commit_and_push handler
# ═══════════════════════════════════════════════════════════════════════

class TestGitCommitAndPush:
    def test_missing_commit_message(self):
        req = ActionRequest(
            capability="git_commit_and_push",
            params={},
        )
        result = git_commit_and_push(req)
        assert result.status == ActionStatus.FAILED
        assert "commit_message" in result.detail

    def test_no_local_repo(self, tmp_path):
        req = ActionRequest(
            capability="git_commit_and_push",
            params={"commit_message": "test"},
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path / "nonexistent")
            mock_cfg.GIT_FORK_OWNER = ""
            result = git_commit_and_push(req)
        assert result.status == ActionStatus.FAILED

    @patch("src.executor.handlers.git_ops._run_git")
    @patch("src.executor.handlers.git_ops._ensure_authenticated_remote")
    def test_no_changes(self, mock_auth, mock_git, tmp_path):
        # Create fake .git directory
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        mock_git.side_effect = [
            MagicMock(returncode=0),  # git add -A
            MagicMock(returncode=0, stdout=""),  # git status --porcelain
        ]

        req = ActionRequest(
            capability="git_commit_and_push",
            params={"commit_message": "test"},
            resolved_write_dirs=[str(tmp_path)],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REMOTE_URL = ""
            result = git_commit_and_push(req)

        assert result.status == ActionStatus.SUCCESS
        assert "No changes" in result.detail

    @patch("src.executor.handlers.git_ops._run_git")
    @patch("src.executor.handlers.git_ops._ensure_authenticated_remote")
    def test_branch_with_conflicting_prefix_ref(self, mock_auth, mock_git, tmp_path):
        """Checkout ai-rules/20260326 when local branch 'ai-rules' exists."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        mock_git.side_effect = [
            # _delete_conflicting_refs: git branch --list
            MagicMock(returncode=0, stdout="* main\n  ai-rules\n"),
            # _delete_conflicting_refs: git branch -D ai-rules
            MagicMock(returncode=0),
            # git rev-parse --verify ai-rules/20260326
            MagicMock(returncode=1),
            # git checkout -b ai-rules/20260326
            MagicMock(returncode=0),
            # git add -A
            MagicMock(returncode=0),
            # git status --porcelain
            MagicMock(returncode=0, stdout="M rules/test.rules\n"),
            # git commit
            MagicMock(returncode=0),
            # _delete_conflicting_remote_refs: git ls-remote --heads origin
            MagicMock(returncode=0, stdout="abc123\trefs/heads/ai-rules\n"),
            # _delete_conflicting_remote_refs: git push origin --delete ai-rules
            MagicMock(returncode=0),
            # git push
            MagicMock(returncode=0),
        ]

        req = ActionRequest(
            capability="git_commit_and_push",
            params={
                "commit_message": "[AI] test",
                "branch": "ai-rules/20260326",
            },
            resolved_write_dirs=[str(tmp_path)],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REMOTE_URL = ""
            result = git_commit_and_push(req)

        assert result.status == ActionStatus.SUCCESS
        # Verify conflicting branch was deleted
        delete_call = mock_git.call_args_list[1]
        assert delete_call[0][0] == ["branch", "-D", "ai-rules"]


# ═══════════════════════════════════════════════════════════════════════
# _delete_conflicting_refs
# ═══════════════════════════════════════════════════════════════════════

class TestDeleteConflictingRefs:
    @patch("src.executor.handlers.git_ops._run_git")
    def test_prefix_conflict_deleted(self, mock_git):
        """'ai-rules' is deleted when creating 'ai-rules/20260326'."""
        mock_git.return_value = MagicMock(
            returncode=0, stdout="* main\n  ai-rules\n"
        )
        _delete_conflicting_refs("ai-rules/20260326")
        calls = [c[0][0] for c in mock_git.call_args_list]
        assert ["branch", "--list"] in calls
        assert ["branch", "-D", "ai-rules"] in calls

    @patch("src.executor.handlers.git_ops._run_git")
    def test_child_conflict_deleted(self, mock_git):
        """'ai-rules/20260325' is deleted when creating 'ai-rules'."""
        mock_git.return_value = MagicMock(
            returncode=0, stdout="* main\n  ai-rules/20260325\n"
        )
        _delete_conflicting_refs("ai-rules")
        calls = [c[0][0] for c in mock_git.call_args_list]
        assert ["branch", "-D", "ai-rules/20260325"] in calls

    @patch("src.executor.handlers.git_ops._run_git")
    def test_no_conflict(self, mock_git):
        """No branches deleted when there's no conflict."""
        mock_git.return_value = MagicMock(
            returncode=0, stdout="* main\n  feature/other\n"
        )
        _delete_conflicting_refs("ai-rules/20260326")
        calls = [c[0][0] for c in mock_git.call_args_list]
        assert calls == [["branch", "--list"]]

    @patch("src.executor.handlers.git_ops._run_git")
    def test_branch_list_failure(self, mock_git):
        """Graceful exit when git branch --list fails."""
        mock_git.return_value = MagicMock(returncode=1, stdout="")
        _delete_conflicting_refs("ai-rules/20260326")
        assert mock_git.call_count == 1

    @patch("src.executor.handlers.git_ops._run_git")
    def test_multiple_child_conflicts(self, mock_git):
        """Multiple conflicting child branches are all deleted."""
        mock_git.return_value = MagicMock(
            returncode=0,
            stdout="* main\n  ai-rules/20260324\n  ai-rules/20260325\n",
        )
        _delete_conflicting_refs("ai-rules")
        calls = [c[0][0] for c in mock_git.call_args_list]
        assert ["branch", "-D", "ai-rules/20260324"] in calls
        assert ["branch", "-D", "ai-rules/20260325"] in calls


# ═══════════════════════════════════════════════════════════════════════
# _delete_conflicting_remote_refs
# ═══════════════════════════════════════════════════════════════════════

class TestDeleteConflictingRemoteRefs:
    @patch("src.executor.handlers.git_ops._run_git")
    def test_prefix_conflict_deleted(self, mock_git):
        """Remote 'ai-rules' is deleted when pushing 'ai-rules/20260326'."""
        mock_git.side_effect = [
            # git ls-remote --heads origin
            MagicMock(returncode=0, stdout="abc123\trefs/heads/ai-rules\nabc456\trefs/heads/main\n"),
            # git push origin --delete ai-rules
            MagicMock(returncode=0),
        ]
        _delete_conflicting_remote_refs("ai-rules/20260326")
        calls = [c[0][0] for c in mock_git.call_args_list]
        assert ["ls-remote", "--heads", "origin"] in calls
        assert ["push", "origin", "--delete", "ai-rules"] in calls

    @patch("src.executor.handlers.git_ops._run_git")
    def test_child_conflict_deleted(self, mock_git):
        """Remote 'ai-rules/20260325' is deleted when pushing 'ai-rules'."""
        mock_git.side_effect = [
            MagicMock(returncode=0, stdout="abc123\trefs/heads/ai-rules/20260325\n"),
            MagicMock(returncode=0),
        ]
        _delete_conflicting_remote_refs("ai-rules")
        calls = [c[0][0] for c in mock_git.call_args_list]
        assert ["push", "origin", "--delete", "ai-rules/20260325"] in calls

    @patch("src.executor.handlers.git_ops._run_git")
    def test_no_conflict(self, mock_git):
        """No remote branches deleted when there's no conflict."""
        mock_git.return_value = MagicMock(
            returncode=0, stdout="abc123\trefs/heads/main\nabc456\trefs/heads/feature/other\n"
        )
        _delete_conflicting_remote_refs("ai-rules/20260326")
        assert mock_git.call_count == 1  # only ls-remote

    @patch("src.executor.handlers.git_ops._run_git")
    def test_ls_remote_failure(self, mock_git):
        """Graceful exit when git ls-remote fails."""
        mock_git.return_value = MagicMock(returncode=1, stdout="")
        _delete_conflicting_remote_refs("ai-rules/20260326")
        assert mock_git.call_count == 1


# ═══════════════════════════════════════════════════════════════════════
# git_repo_reset handler
# ═══════════════════════════════════════════════════════════════════════

class TestGitRepoReset:
    def test_no_local_repo(self, tmp_path):
        req = ActionRequest(capability="git_repo_reset", params={})
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path / "nonexistent")
            mock_cfg.GIT_FORK_OWNER = ""
            result = git_repo_reset(req)
        assert result.status == ActionStatus.FAILED
        assert "not found" in result.detail

    def test_pathguard_denied(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        req = ActionRequest(
            capability="git_repo_reset",
            params={},
            resolved_write_dirs=["/some/other/dir"],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_FORK_OWNER = ""
            result = git_repo_reset(req)
        assert result.status == ActionStatus.FAILED
        assert "PathGuard" in result.detail

    @patch("src.executor.handlers.git_ops._run_git")
    @patch("src.executor.handlers.git_ops._ensure_authenticated_remote")
    def test_pull_failure(self, mock_auth, mock_git, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        mock_git.side_effect = [
            MagicMock(returncode=0),  # checkout main
            MagicMock(returncode=0),  # restore .
            MagicMock(returncode=0),  # clean -fd
            MagicMock(returncode=1, stderr="network error"),  # pull fails
        ]
        req = ActionRequest(
            capability="git_repo_reset",
            params={},
            resolved_write_dirs=[str(tmp_path)],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REMOTE_URL = ""
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            result = git_repo_reset(req)
        assert result.status == ActionStatus.FAILED
        assert "git pull failed" in result.detail

    @patch("src.executor.handlers.git_ops._run_git")
    @patch("src.executor.handlers.git_ops._ensure_authenticated_remote")
    def test_success_no_extra_branches(self, mock_auth, mock_git, tmp_path):
        """Reset succeeds when only the default branch exists."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        mock_git.side_effect = [
            MagicMock(returncode=0),  # checkout main
            MagicMock(returncode=0),  # restore .
            MagicMock(returncode=0),  # clean -fd
            MagicMock(returncode=0),  # pull
            MagicMock(returncode=0, stdout="* main\n"),  # branch --list
            MagicMock(returncode=0),  # remote prune origin
            MagicMock(returncode=0),  # pack-refs --all
        ]
        req = ActionRequest(
            capability="git_repo_reset",
            params={},
            resolved_write_dirs=[str(tmp_path)],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REMOTE_URL = ""
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            result = git_repo_reset(req)
        assert result.status == ActionStatus.SUCCESS
        assert "main" in result.detail
        # Verify pack-refs was called
        calls = [c[0][0] for c in mock_git.call_args_list]
        assert ["pack-refs", "--all"] in calls

    @patch("src.executor.handlers.git_ops._run_git")
    @patch("src.executor.handlers.git_ops._ensure_authenticated_remote")
    def test_deletes_local_and_remote_branches(self, mock_auth, mock_git, tmp_path):
        """Feature branches are deleted both locally and on the remote."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        mock_git.side_effect = [
            MagicMock(returncode=0),  # checkout main
            MagicMock(returncode=0),  # restore .
            MagicMock(returncode=0),  # clean -fd
            MagicMock(returncode=0),  # pull
            MagicMock(returncode=0, stdout="* main\n  ai-rules/20260325\n  ai-rules/20260326\n"),  # branch --list
            MagicMock(returncode=0),  # branch -D ai-rules/20260325
            MagicMock(returncode=0),  # push --delete ai-rules/20260325
            MagicMock(returncode=0),  # branch -D ai-rules/20260326
            MagicMock(returncode=0),  # push --delete ai-rules/20260326
            MagicMock(returncode=0),  # remote prune origin
            MagicMock(returncode=0),  # pack-refs --all
        ]
        req = ActionRequest(
            capability="git_repo_reset",
            params={},
            resolved_write_dirs=[str(tmp_path)],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REMOTE_URL = ""
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            result = git_repo_reset(req)
        assert result.status == ActionStatus.SUCCESS
        calls = [c[0][0] for c in mock_git.call_args_list]
        assert ["branch", "-D", "ai-rules/20260325"] in calls
        assert ["push", "origin", "--delete", "ai-rules/20260325"] in calls
        assert ["branch", "-D", "ai-rules/20260326"] in calls
        assert ["push", "origin", "--delete", "ai-rules/20260326"] in calls

    @patch("src.executor.handlers.git_ops._run_git")
    @patch("src.executor.handlers.git_ops._ensure_authenticated_remote")
    def test_remote_delete_failure_is_nonfatal(self, mock_auth, mock_git, tmp_path):
        """Remote branch deletion failure does not block the reset."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        mock_git.side_effect = [
            MagicMock(returncode=0),  # checkout main
            MagicMock(returncode=0),  # restore .
            MagicMock(returncode=0),  # clean -fd
            MagicMock(returncode=0),  # pull
            MagicMock(returncode=0, stdout="* main\n  stale-branch\n"),  # branch --list
            MagicMock(returncode=0),  # branch -D stale-branch
            MagicMock(returncode=1, stderr="error: unable to delete"),  # push --delete fails
            MagicMock(returncode=0),  # remote prune origin
            MagicMock(returncode=0),  # pack-refs --all
        ]
        req = ActionRequest(
            capability="git_repo_reset",
            params={},
            resolved_write_dirs=[str(tmp_path)],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REMOTE_URL = ""
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            result = git_repo_reset(req)
        assert result.status == ActionStatus.SUCCESS

    @patch("src.executor.handlers.git_ops._run_git")
    @patch("src.executor.handlers.git_ops._ensure_authenticated_remote")
    def test_default_branch_not_deleted(self, mock_auth, mock_git, tmp_path):
        """The default branch itself is never deleted."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        mock_git.side_effect = [
            MagicMock(returncode=0),  # checkout main
            MagicMock(returncode=0),  # restore .
            MagicMock(returncode=0),  # clean -fd
            MagicMock(returncode=0),  # pull
            MagicMock(returncode=0, stdout="* main\n  feature-x\n"),  # branch --list
            MagicMock(returncode=0),  # branch -D feature-x
            MagicMock(returncode=0),  # push --delete feature-x
            MagicMock(returncode=0),  # remote prune origin
            MagicMock(returncode=0),  # pack-refs --all
        ]
        req = ActionRequest(
            capability="git_repo_reset",
            params={},
            resolved_write_dirs=[str(tmp_path)],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REMOTE_URL = ""
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            result = git_repo_reset(req)
        assert result.status == ActionStatus.SUCCESS
        calls = [c[0][0] for c in mock_git.call_args_list]
        # main should never appear in a -D call
        delete_calls = [c for c in calls if c[0] == "branch" and "-D" in c]
        for dc in delete_calls:
            assert dc[-1] != "main"


# ═══════════════════════════════════════════════════════════════════════
# git_clone_repo handler
# ═══════════════════════════════════════════════════════════════════════

class TestGitCloneRepo:
    def test_no_remote_url(self):
        req = ActionRequest(capability="git_clone_repo", params={})
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_REMOTE_URL = ""
            mock_cfg.GIT_LOCAL_REPO_PATH = "/tmp/test"
            mock_cfg.GIT_TOKEN = ""
            mock_cfg.GIT_FORK_OWNER = ""
            result = git_clone_repo(req)
        assert result.status == ActionStatus.FAILED
        assert "remote URL" in result.detail or "remote_url" in result.detail

    def test_already_cloned(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        req = ActionRequest(capability="git_clone_repo", params={})
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_REMOTE_URL = "https://github.com/test/repo.git"
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = ""
            result = git_clone_repo(req)
        assert result.status == ActionStatus.SUCCESS
        assert "already exists" in result.detail


# ═══════════════════════════════════════════════════════════════════════
# Fork mode helpers
# ═══════════════════════════════════════════════════════════════════════

class TestForkHelpers:
    def test_fork_mode_true(self):
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            assert _fork_mode() is True

    def test_fork_mode_false(self):
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_FORK_OWNER = ""
            assert _fork_mode() is False

    def test_fork_remote_url(self):
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            mock_cfg.GIT_REPO_NAME = "capri-customized-suricata-rules"
            url = _fork_remote_url()
        assert url == "https://github.com/capri-ai-bot/capri-customized-suricata-rules.git"

    def test_upstream_remote_url_uses_remote_url(self):
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_REMOTE_URL = "https://github.com/owner/repo.git"
            url = _upstream_remote_url()
        assert url == "https://github.com/owner/repo.git"

    def test_upstream_remote_url_builds_from_parts(self):
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_REMOTE_URL = ""
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_REPO_OWNER = "test-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            url = _upstream_remote_url()
        assert url == "https://github.com/test-owner/test-repo.git"


# ═══════════════════════════════════════════════════════════════════════
# Fork mode: create_github_pr (cross-repo PR)
# ═══════════════════════════════════════════════════════════════════════

class TestCreateGitHubPrForkMode:
    @patch("src.executor.handlers.git_ops.requests.post")
    def test_cross_repo_pr_head_format(self, mock_post):
        """In fork mode, head is 'fork_owner:branch'."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"number": 42, "html_url": "https://github.com/test/pull/42"}
        mock_post.return_value = mock_resp

        req = ActionRequest(
            capability="create_github_pr",
            params={
                "title": "[AI] Rules",
                "head_branch": "main",
                "base_branch": "main",
            },
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            mock_cfg.GIT_REPO_OWNER = "upstream-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            result = create_github_pr(req)

        assert result.status == ActionStatus.SUCCESS
        # Verify the payload sent to GitHub has cross-repo head
        call_kwargs = mock_post.call_args
        payload = call_kwargs[1]["json"] if "json" in call_kwargs[1] else call_kwargs.kwargs["json"]
        assert payload["head"] == "capri-ai-bot:main"


# ═══════════════════════════════════════════════════════════════════════
# Fork mode: git_commit_and_push (no branch creation)
# ═══════════════════════════════════════════════════════════════════════

class TestGitCommitAndPushForkMode:
    @patch("src.executor.handlers.git_ops._run_git")
    @patch("src.executor.handlers.git_ops._ensure_authenticated_remote")
    def test_fork_mode_ignores_branch(self, mock_auth, mock_git, tmp_path):
        """Fork mode skips branch creation and pushes to HEAD."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        mock_git.side_effect = [
            # git add -A
            MagicMock(returncode=0),
            # git status --porcelain
            MagicMock(returncode=0, stdout="M rules/test.rules\n"),
            # git commit
            MagicMock(returncode=0),
            # git push origin HEAD
            MagicMock(returncode=0),
        ]

        req = ActionRequest(
            capability="git_commit_and_push",
            params={
                "commit_message": "[AI] test",
                "branch": "ai-rules/20260328",  # should be ignored
            },
            resolved_write_dirs=[str(tmp_path)],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_REMOTE_URL = ""
            result = git_commit_and_push(req)

        assert result.status == ActionStatus.SUCCESS
        calls = [c[0][0] for c in mock_git.call_args_list]
        # No branch checkout or delete calls
        assert ["checkout", "-b", "ai-rules/20260328"] not in calls
        assert ["branch", "--list"] not in calls
        # Push should be plain HEAD, not HEAD:refs/heads/...
        assert ["push", "origin", "HEAD"] in calls


# ═══════════════════════════════════════════════════════════════════════
# Fork mode: git_repo_reset (upstream sync)
# ═══════════════════════════════════════════════════════════════════════

class TestGitRepoResetForkMode:
    @patch("src.executor.handlers.git_ops._run_git")
    @patch("src.executor.handlers.git_ops._ensure_authenticated_remote")
    def test_fork_reset_syncs_upstream(self, mock_auth, mock_git, tmp_path):
        """Fork mode fetches upstream and force-pushes to origin."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        mock_git.side_effect = [
            MagicMock(returncode=0),  # checkout main
            MagicMock(returncode=0),  # restore .
            MagicMock(returncode=0),  # clean -fd
            MagicMock(returncode=0),  # remote remove upstream (may fail, ok)
            MagicMock(returncode=0),  # remote add upstream
            MagicMock(returncode=0),  # fetch upstream main
            MagicMock(returncode=0),  # reset --hard upstream/main
            MagicMock(returncode=0),  # push origin main --force
            MagicMock(returncode=0),  # remote prune origin
            MagicMock(returncode=0),  # pack-refs --all
        ]

        req = ActionRequest(
            capability="git_repo_reset",
            params={},
            resolved_write_dirs=[str(tmp_path)],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            mock_cfg.GIT_REPO_OWNER = "upstream-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_REMOTE_URL = "https://github.com/upstream-owner/test-repo.git"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            result = git_repo_reset(req)

        assert result.status == ActionStatus.SUCCESS
        calls = [c[0][0] for c in mock_git.call_args_list]
        assert ["fetch", "upstream", "main"] in calls
        assert ["reset", "--hard", "upstream/main"] in calls
        assert ["push", "origin", "main", "--force"] in calls
        # No branch --list (same-repo branch cleanup) in fork mode
        assert ["branch", "--list"] not in calls

    @patch("src.executor.handlers.git_ops._run_git")
    @patch("src.executor.handlers.git_ops._ensure_authenticated_remote")
    def test_fork_reset_fetch_failure(self, mock_auth, mock_git, tmp_path):
        """Fetch upstream failure is reported."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        mock_git.side_effect = [
            MagicMock(returncode=0),  # checkout main
            MagicMock(returncode=0),  # restore .
            MagicMock(returncode=0),  # clean -fd
            MagicMock(returncode=0),  # remote remove upstream
            MagicMock(returncode=0),  # remote add upstream
            MagicMock(returncode=1, stderr="network error"),  # fetch fails
        ]

        req = ActionRequest(
            capability="git_repo_reset",
            params={},
            resolved_write_dirs=[str(tmp_path)],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            mock_cfg.GIT_REPO_OWNER = "upstream-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_REMOTE_URL = "https://github.com/upstream-owner/test-repo.git"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            result = git_repo_reset(req)

        assert result.status == ActionStatus.FAILED
        assert "fetch upstream" in result.detail


# ═══════════════════════════════════════════════════════════════════════
# Fork mode: git_clone_repo (clone fork + add upstream)
# ═══════════════════════════════════════════════════════════════════════

class TestGitCloneRepoForkMode:
    @patch("src.executor.handlers.git_ops.subprocess.run")
    @patch("src.executor.handlers.git_ops._run_git")
    def test_clone_fork_adds_upstream(self, mock_run_git, mock_subprocess, tmp_path):
        """Fork mode clones the fork URL and adds upstream remote."""
        repo_path = tmp_path / "workspace"

        mock_subprocess.return_value = MagicMock(returncode=0)
        mock_run_git.return_value = MagicMock(returncode=0)

        req = ActionRequest(
            capability="git_clone_repo",
            params={},
            resolved_write_dirs=[str(repo_path)],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            mock_cfg.GIT_REPO_OWNER = "upstream-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_REMOTE_URL = "https://github.com/upstream-owner/test-repo.git"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_LOCAL_REPO_PATH = str(repo_path)
            result = git_clone_repo(req)

        assert result.status == ActionStatus.SUCCESS
        # Verify clone used fork URL
        clone_args = mock_subprocess.call_args[0][0]
        assert "capri-ai-bot" in clone_args[2]  # URL contains fork owner
        # Verify upstream remote was added
        run_git_calls = [c[0][0] for c in mock_run_git.call_args_list]
        upstream_add = [c for c in run_git_calls if c[:2] == ["remote", "add"] and "upstream" in c]
        assert len(upstream_add) == 1


# ═══════════════════════════════════════════════════════════════════════
# close_github_prs handler
# ═══════════════════════════════════════════════════════════════════════

class TestCloseGitHubPrs:
    def test_no_fork_owner(self):
        req = ActionRequest(capability="close_github_prs", params={})
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REPO_OWNER = "test-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            result = close_github_prs(req)
        assert result.status == ActionStatus.FAILED
        assert "fork_owner" in result.detail

    @patch("src.executor.handlers.git_ops.requests.get")
    def test_no_open_prs(self, mock_get):
        """No-op when there are no open PRs from the fork."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        req = ActionRequest(capability="close_github_prs", params={})
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            mock_cfg.GIT_REPO_OWNER = "upstream-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            result = close_github_prs(req)
        assert result.status == ActionStatus.SUCCESS
        assert "No open PRs" in result.detail

    @patch("src.executor.handlers.git_ops.requests.patch")
    @patch("src.executor.handlers.git_ops.requests.get")
    def test_closes_open_prs(self, mock_get, mock_patch):
        """Open PRs are closed via PATCH."""
        mock_list_resp = MagicMock()
        mock_list_resp.json.return_value = [
            {"number": 5, "html_url": "https://github.com/test/pull/5"},
            {"number": 8, "html_url": "https://github.com/test/pull/8"},
        ]
        mock_list_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_list_resp

        mock_close_resp = MagicMock()
        mock_close_resp.ok = True
        mock_patch.return_value = mock_close_resp

        req = ActionRequest(capability="close_github_prs", params={})
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            mock_cfg.GIT_REPO_OWNER = "upstream-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            result = close_github_prs(req)
        assert result.status == ActionStatus.SUCCESS
        assert result.output["closed"] == [5, 8]
        assert mock_patch.call_count == 2

    @patch("src.executor.handlers.git_ops.requests.get")
    def test_head_filter_includes_default_branch(self, mock_get):
        """Verify the 'head' query parameter includes fork_owner:default_branch."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        req = ActionRequest(capability="close_github_prs", params={})
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            mock_cfg.GIT_REPO_OWNER = "upstream-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_DEFAULT_BRANCH = "develop"
            close_github_prs(req)

        # Extract the params passed to requests.get
        call_kwargs = mock_get.call_args
        params = call_kwargs[1].get("params") or call_kwargs.kwargs.get("params")
        assert params["head"] == "capri-ai-bot:develop"
        assert params["state"] == "open"


# ═══════════════════════════════════════════════════════════════════════
# _effective_remote_url
# ═══════════════════════════════════════════════════════════════════════

class TestEffectiveRemoteUrl:
    def test_fork_mode_returns_fork_url(self):
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_REMOTE_URL = "https://github.com/upstream/test-repo.git"
            url = _effective_remote_url()
        assert "capri-ai-bot" in url
        assert url == "https://github.com/capri-ai-bot/test-repo.git"

    def test_non_fork_mode_returns_remote_url(self):
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REMOTE_URL = "https://github.com/upstream/test-repo.git"
            url = _effective_remote_url()
        assert url == "https://github.com/upstream/test-repo.git"


# ═══════════════════════════════════════════════════════════════════════
# GitHub Enterprise URL construction
# ═══════════════════════════════════════════════════════════════════════

class TestGitHubEnterpriseUrls:
    def test_fork_remote_url_ghe(self):
        """GitHub Enterprise: strip /api/v3 to get host."""
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_API_BASE_URL = "https://git.example.com/api/v3"
            mock_cfg.GIT_FORK_OWNER = "bot-user"
            mock_cfg.GIT_REPO_NAME = "rules"
            url = _fork_remote_url()
        assert url == "https://git.example.com/bot-user/rules.git"

    def test_upstream_remote_url_ghe_fallback(self):
        """GitHub Enterprise: build URL from parts when GIT_REMOTE_URL is empty."""
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_REMOTE_URL = ""
            mock_cfg.GIT_API_BASE_URL = "https://git.example.com/api/v3"
            mock_cfg.GIT_REPO_OWNER = "org"
            mock_cfg.GIT_REPO_NAME = "rules"
            url = _upstream_remote_url()
        assert url == "https://git.example.com/org/rules.git"


# ═══════════════════════════════════════════════════════════════════════
# close_github_prs: additional edge cases
# ═══════════════════════════════════════════════════════════════════════

class TestCloseGitHubPrsEdgeCases:
    def test_missing_repo_config(self):
        """Fail when repo_owner/repo_name are not configured."""
        req = ActionRequest(capability="close_github_prs", params={})
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            mock_cfg.GIT_REPO_OWNER = ""
            mock_cfg.GIT_REPO_NAME = ""
            result = close_github_prs(req)
        assert result.status == ActionStatus.FAILED
        assert "repo_owner" in result.detail

    @patch("src.executor.handlers.git_ops.requests.get")
    def test_http_error(self, mock_get):
        """HTTPError during PR listing is handled gracefully."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.HTTPError(
            response=MagicMock(status_code=403, text="Forbidden")
        )
        mock_get.return_value = mock_resp

        req = ActionRequest(capability="close_github_prs", params={})
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            mock_cfg.GIT_REPO_OWNER = "upstream-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            result = close_github_prs(req)
        assert result.status == ActionStatus.FAILED
        assert "GitHub API error" in result.detail or "403" in result.detail or "Forbidden" in result.detail

    @patch("src.executor.handlers.git_ops.requests.patch")
    @patch("src.executor.handlers.git_ops.requests.get")
    def test_partial_close_failure(self, mock_get, mock_patch):
        """If one PR PATCH fails, the others are still closed."""
        mock_list_resp = MagicMock()
        mock_list_resp.json.return_value = [
            {"number": 1},
            {"number": 2},
            {"number": 3},
        ]
        mock_list_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_list_resp

        # PR #2 fails to close
        mock_patch.side_effect = [
            MagicMock(ok=True),   # PR #1 closed
            MagicMock(ok=False, text="Internal Server Error"),  # PR #2 fails
            MagicMock(ok=True),   # PR #3 closed
        ]

        req = ActionRequest(capability="close_github_prs", params={})
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            mock_cfg.GIT_REPO_OWNER = "upstream-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            result = close_github_prs(req)
        assert result.status == ActionStatus.SUCCESS
        assert result.output["closed"] == [1, 3]


# ═══════════════════════════════════════════════════════════════════════
# _delete_conflicting_remote_refs: additional edge cases
# ═══════════════════════════════════════════════════════════════════════

class TestDeleteConflictingRemoteRefsEdgeCases:
    @patch("src.executor.handlers.git_ops._run_git")
    def test_multi_level_path_prefix(self, mock_git):
        """Branch 'a/b/c' should delete remote 'a' and 'a/b'."""
        mock_git.side_effect = [
            MagicMock(returncode=0, stdout=(
                "abc\trefs/heads/a\n"
                "def\trefs/heads/a/b\n"
                "ghi\trefs/heads/main\n"
            )),
            MagicMock(returncode=0),  # delete a
            MagicMock(returncode=0),  # delete a/b
        ]
        _delete_conflicting_remote_refs("a/b/c")
        calls = [c[0][0] for c in mock_git.call_args_list]
        assert ["push", "origin", "--delete", "a"] in calls
        assert ["push", "origin", "--delete", "a/b"] in calls

    @patch("src.executor.handlers.git_ops._run_git")
    def test_multiple_child_conflicts(self, mock_git):
        """Multiple remote children are all deleted."""
        mock_git.side_effect = [
            MagicMock(returncode=0, stdout=(
                "abc\trefs/heads/ai-rules/20260325\n"
                "def\trefs/heads/ai-rules/20260326\n"
                "ghi\trefs/heads/ai-rules/20260327\n"
            )),
            MagicMock(returncode=0),  # delete 20260325
            MagicMock(returncode=0),  # delete 20260326
            MagicMock(returncode=0),  # delete 20260327
        ]
        _delete_conflicting_remote_refs("ai-rules")
        calls = [c[0][0] for c in mock_git.call_args_list]
        assert ["push", "origin", "--delete", "ai-rules/20260325"] in calls
        assert ["push", "origin", "--delete", "ai-rules/20260326"] in calls
        assert ["push", "origin", "--delete", "ai-rules/20260327"] in calls

    @patch("src.executor.handlers.git_ops._run_git")
    def test_malformed_ls_remote_output(self, mock_git):
        """Malformed lines in ls-remote are silently skipped."""
        mock_git.return_value = MagicMock(
            returncode=0, stdout="no-tab-here\nbad line\n"
        )
        # Should not raise
        _delete_conflicting_remote_refs("ai-rules/20260326")
        assert mock_git.call_count == 1


# ═══════════════════════════════════════════════════════════════════════
# Fork mode: git_repo_reset push --force failure
# ═══════════════════════════════════════════════════════════════════════

class TestGitRepoResetForkPushFailure:
    @patch("src.executor.handlers.git_ops._run_git")
    @patch("src.executor.handlers.git_ops._ensure_authenticated_remote")
    def test_force_push_failure_reported(self, mock_auth, mock_git, tmp_path):
        """push --force failure returns FAILED."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        mock_git.side_effect = [
            MagicMock(returncode=0),  # checkout main
            MagicMock(returncode=0),  # restore .
            MagicMock(returncode=0),  # clean -fd
            MagicMock(returncode=0),  # remote remove upstream
            MagicMock(returncode=0),  # remote add upstream
            MagicMock(returncode=0),  # fetch upstream main
            MagicMock(returncode=0),  # reset --hard upstream/main
            MagicMock(returncode=1, stderr="rejected"),  # push --force fails
        ]

        req = ActionRequest(
            capability="git_repo_reset",
            params={},
            resolved_write_dirs=[str(tmp_path)],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            mock_cfg.GIT_REPO_OWNER = "upstream-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_REMOTE_URL = "https://github.com/upstream-owner/test-repo.git"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            result = git_repo_reset(req)

        assert result.status == ActionStatus.FAILED
        assert "push --force" in result.detail


# ═══════════════════════════════════════════════════════════════════════
# git_clone_repo: full clone flow (non-fork)
# ═══════════════════════════════════════════════════════════════════════

class TestGitCloneRepoFullFlow:
    @patch("src.executor.handlers.git_ops.subprocess.run")
    @patch("src.executor.handlers.git_ops._run_git")
    def test_clone_success_non_fork(self, mock_run_git, mock_subprocess, tmp_path):
        """Non-fork mode: clone, set url, configure user, no upstream."""
        repo_path = tmp_path / "workspace"

        mock_subprocess.return_value = MagicMock(returncode=0)
        mock_run_git.return_value = MagicMock(returncode=0)

        req = ActionRequest(
            capability="git_clone_repo",
            params={},
            resolved_write_dirs=[str(repo_path)],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REPO_OWNER = "test-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_REMOTE_URL = "https://github.com/test-owner/test-repo.git"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_LOCAL_REPO_PATH = str(repo_path)
            result = git_clone_repo(req)

        assert result.status == ActionStatus.SUCCESS
        # Verify no upstream remote was added (non-fork mode)
        run_git_calls = [c[0][0] for c in mock_run_git.call_args_list]
        upstream_adds = [c for c in run_git_calls if "upstream" in c]
        assert len(upstream_adds) == 0

    @patch("src.executor.handlers.git_ops.subprocess.run")
    def test_clone_failure(self, mock_subprocess, tmp_path):
        """Clone failure returns FAILED."""
        repo_path = tmp_path / "workspace"
        mock_subprocess.return_value = MagicMock(
            returncode=128, stderr="fatal: repository not found"
        )

        req = ActionRequest(
            capability="git_clone_repo",
            params={},
            resolved_write_dirs=[str(repo_path)],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = ""
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REPO_OWNER = "test-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_REMOTE_URL = "https://github.com/test-owner/test-repo.git"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_LOCAL_REPO_PATH = str(repo_path)
            result = git_clone_repo(req)

        assert result.status == ActionStatus.FAILED
        assert "clone failed" in result.detail

class TestIssueDedupCache:
    def test_add_and_has(self):
        from src.processor import _IssueDedupCache
        cache = _IssueDedupCache(max_size=10, ttl_seconds=3600)
        assert cache.check_and_add("key1") is True  # new
        assert cache.check_and_add("key1") is False  # duplicate

    def test_max_size_eviction(self):
        from src.processor import _IssueDedupCache
        cache = _IssueDedupCache(max_size=3, ttl_seconds=3600)
        cache.check_and_add("a")
        cache.check_and_add("b")
        cache.check_and_add("c")
        cache.check_and_add("d")
        # "a" should have been evicted
        assert cache.check_and_add("a") is True  # evicted, so new again
        assert cache.check_and_add("d") is False  # still present

    def test_ttl_expiry(self):
        import time
        from src.processor import _IssueDedupCache
        cache = _IssueDedupCache(max_size=10, ttl_seconds=0)
        cache.check_and_add("key")
        time.sleep(0.05)
        assert cache.check_and_add("key") is True  # expired, so new again


# ═══════════════════════════════════════════════════════════════════════
# _delete_conflicting_refs: simple branch name (no hierarchy)
# ═══════════════════════════════════════════════════════════════════════

class TestDeleteConflictingRefsSimpleBranch:
    @patch("src.executor.handlers.git_ops._run_git")
    def test_simple_name_no_conflict(self, mock_git):
        """A simple branch name like 'feature' has no prefix to conflict."""
        mock_git.return_value = MagicMock(
            returncode=0, stdout="* main\n  other-branch\n"
        )
        _delete_conflicting_refs("feature")
        calls = [c[0][0] for c in mock_git.call_args_list]
        # Only branch --list should be called; no deletion
        assert calls == [["branch", "--list"]]

    @patch("src.executor.handlers.git_ops._run_git")
    def test_simple_name_with_child_conflict(self, mock_git):
        """Branch 'ai-rules' deletes child 'ai-rules/old'."""
        mock_git.return_value = MagicMock(
            returncode=0, stdout="* main\n  ai-rules/old\n  ai-rules/older\n"
        )
        _delete_conflicting_refs("ai-rules")
        calls = [c[0][0] for c in mock_git.call_args_list]
        assert ["branch", "-D", "ai-rules/old"] in calls
        assert ["branch", "-D", "ai-rules/older"] in calls


# ═══════════════════════════════════════════════════════════════════════
# _effective_remote_url: GitHub Enterprise
# ═══════════════════════════════════════════════════════════════════════

class TestEffectiveRemoteUrlGHE:
    def test_fork_mode_ghe(self):
        """GitHub Enterprise fork mode builds URL from GHE host."""
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_FORK_OWNER = "bot-user"
            mock_cfg.GIT_API_BASE_URL = "https://git.corp.example.com/api/v3"
            mock_cfg.GIT_REPO_NAME = "sec-rules"
            mock_cfg.GIT_REMOTE_URL = "https://git.corp.example.com/org/sec-rules.git"
            url = _effective_remote_url()
        assert url == "https://git.corp.example.com/bot-user/sec-rules.git"

    def test_non_fork_mode_ghe(self):
        """GitHub Enterprise non-fork mode returns configured remote URL."""
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REMOTE_URL = "https://git.corp.example.com/org/sec-rules.git"
            url = _effective_remote_url()
        assert url == "https://git.corp.example.com/org/sec-rules.git"


# ═══════════════════════════════════════════════════════════════════════
# close_github_prs: generic exception handling
# ═══════════════════════════════════════════════════════════════════════

class TestCloseGitHubPrsGenericException:
    @patch("src.executor.handlers.git_ops.requests.get")
    def test_connection_error(self, mock_get):
        """ConnectionError during PR listing is handled gracefully."""
        mock_get.side_effect = requests.ConnectionError("DNS resolution failed")

        req = ActionRequest(capability="close_github_prs", params={})
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = "capri-ai-bot"
            mock_cfg.GIT_REPO_OWNER = "upstream-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            result = close_github_prs(req)
        assert result.status == ActionStatus.FAILED


# ═══════════════════════════════════════════════════════════════════════
# git_clone_repo: fork mode with no remote_url falls back to repo parts
# ═══════════════════════════════════════════════════════════════════════

class TestGitCloneRepoForkNoRemoteUrl:
    @patch("src.executor.handlers.git_ops.subprocess.run")
    @patch("src.executor.handlers.git_ops._run_git")
    def test_fork_mode_empty_remote_url(self, mock_run_git, mock_subprocess, tmp_path):
        """Fork mode with empty remote_url still resolves fork URL from parts."""
        repo_path = tmp_path / "workspace"
        mock_subprocess.return_value = MagicMock(returncode=0)
        mock_run_git.return_value = MagicMock(returncode=0)

        req = ActionRequest(
            capability="git_clone_repo",
            params={},
            resolved_write_dirs=[str(repo_path)],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = "bot-user"
            mock_cfg.GIT_REPO_OWNER = "upstream-org"
            mock_cfg.GIT_REPO_NAME = "rules"
            mock_cfg.GIT_REMOTE_URL = ""
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_LOCAL_REPO_PATH = str(repo_path)
            result = git_clone_repo(req)

        assert result.status == ActionStatus.SUCCESS
        # Verify clone used fork URL derived from parts
        clone_args = mock_subprocess.call_args[0][0]
        assert "bot-user" in clone_args[2]
        assert "rules" in clone_args[2]


# ═══════════════════════════════════════════════════════════════════════
# create_github_pr: HTTP error handling
# ═══════════════════════════════════════════════════════════════════════

class TestCreateGitHubPrHttpError:
    @patch("src.executor.handlers.git_ops.requests.post")
    def test_http_error_handled(self, mock_post):
        """HTTPError during PR creation returns FAILED with detail."""
        mock_resp = MagicMock()
        mock_resp.status_code = 422
        mock_resp.text = "Validation Failed: head branch not found"
        mock_resp.raise_for_status.side_effect = requests.HTTPError(
            response=mock_resp,
        )
        mock_post.return_value = mock_resp

        req = ActionRequest(
            capability="create_github_pr",
            params={
                "title": "PR",
                "head_branch": "nonexistent-branch",
                "base_branch": "main",
            },
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REPO_OWNER = "test-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            result = create_github_pr(req)

        assert result.status == ActionStatus.FAILED
        assert "422" in result.detail

    @patch("src.executor.handlers.git_ops.requests.post")
    def test_generic_exception_handled(self, mock_post):
        """Generic exception during PR creation returns FAILED."""
        mock_post.side_effect = requests.ConnectionError("DNS failed")

        req = ActionRequest(
            capability="create_github_pr",
            params={
                "title": "PR",
                "head_branch": "branch",
                "base_branch": "main",
            },
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REPO_OWNER = "test-owner"
            mock_cfg.GIT_REPO_NAME = "test-repo"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            mock_cfg.GIT_DEFAULT_BRANCH = "main"
            result = create_github_pr(req)

        assert result.status == ActionStatus.FAILED


# ═══════════════════════════════════════════════════════════════════════
# create_github_issue: labels parsing
# ═══════════════════════════════════════════════════════════════════════

class TestCreateGitHubIssueLabels:
    @patch("src.executor.handlers.git_ops.requests.post")
    def test_labels_split_and_trimmed(self, mock_post):
        """Labels string is split by comma and each label is trimmed."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"number": 1, "html_url": "https://example.com"}
        mock_post.return_value = mock_resp

        req = ActionRequest(
            capability="create_github_issue",
            params={"title": "Test", "body": "B", "labels": " bug , auto-alert , 高 "},
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REPO_OWNER = "owner"
            mock_cfg.GIT_REPO_NAME = "repo"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            result = create_github_issue(req)

        assert result.status == ActionStatus.SUCCESS
        payload = mock_post.call_args[1]["json"]
        assert payload["labels"] == ["bug", "auto-alert", "高"]

    @patch("src.executor.handlers.git_ops.requests.post")
    def test_empty_labels_not_sent(self, mock_post):
        """Empty labels string means no labels field in payload."""
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"number": 2, "html_url": "https://example.com"}
        mock_post.return_value = mock_resp

        req = ActionRequest(
            capability="create_github_issue",
            params={"title": "Test", "body": "B", "labels": ""},
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REPO_OWNER = "owner"
            mock_cfg.GIT_REPO_NAME = "repo"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            result = create_github_issue(req)

        assert result.status == ActionStatus.SUCCESS
        payload = mock_post.call_args[1]["json"]
        assert "labels" not in payload

    @patch("src.executor.handlers.git_ops.requests.post")
    def test_http_error_handled(self, mock_post):
        """HTTPError during issue creation returns FAILED with detail."""
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "Forbidden"
        mock_resp.raise_for_status.side_effect = requests.HTTPError(
            response=mock_resp,
        )
        mock_post.return_value = mock_resp

        req = ActionRequest(
            capability="create_github_issue",
            params={"title": "Test", "body": "B"},
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REPO_OWNER = "owner"
            mock_cfg.GIT_REPO_NAME = "repo"
            mock_cfg.GIT_API_BASE_URL = "https://api.github.com"
            result = create_github_issue(req)

        assert result.status == ActionStatus.FAILED
        assert "403" in result.detail


# ═══════════════════════════════════════════════════════════════════════
# git_commit_and_push: full successful flow with branch
# ═══════════════════════════════════════════════════════════════════════

class TestGitCommitAndPushFullFlow:
    @patch("src.executor.handlers.git_ops._run_git")
    @patch("src.executor.handlers.git_ops._ensure_authenticated_remote")
    def test_commit_to_new_branch_success(self, mock_auth, mock_git, tmp_path):
        """Full flow: create branch, add, commit, push with refspec."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        mock_git.side_effect = [
            # _delete_conflicting_refs: git branch --list
            MagicMock(returncode=0, stdout="* main\n"),
            # git rev-parse --verify ai-rules/20260329
            MagicMock(returncode=1),
            # git checkout -b ai-rules/20260329
            MagicMock(returncode=0),
            # git add -A
            MagicMock(returncode=0),
            # git status --porcelain
            MagicMock(returncode=0, stdout="A rules/new.rules\n"),
            # git commit
            MagicMock(returncode=0),
            # _delete_conflicting_remote_refs: git ls-remote --heads origin
            MagicMock(returncode=0, stdout="abc\trefs/heads/main\n"),
            # git push origin HEAD:refs/heads/ai-rules/20260329
            MagicMock(returncode=0),
        ]

        req = ActionRequest(
            capability="git_commit_and_push",
            params={
                "commit_message": "[AI] Add rules",
                "branch": "ai-rules/20260329",
            },
            resolved_write_dirs=[str(tmp_path)],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REMOTE_URL = ""
            result = git_commit_and_push(req)

        assert result.status == ActionStatus.SUCCESS
        assert "ai-rules/20260329" in result.detail
        calls = [c[0][0] for c in mock_git.call_args_list]
        assert ["checkout", "-b", "ai-rules/20260329"] in calls
        assert ["push", "origin", "HEAD:refs/heads/ai-rules/20260329"] in calls

    @patch("src.executor.handlers.git_ops._run_git")
    @patch("src.executor.handlers.git_ops._ensure_authenticated_remote")
    def test_commit_to_existing_branch(self, mock_auth, mock_git, tmp_path):
        """Switch to existing branch instead of creating new."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        mock_git.side_effect = [
            # _delete_conflicting_refs: git branch --list
            MagicMock(returncode=0, stdout="* main\n  feature\n"),
            # git rev-parse --verify feature
            MagicMock(returncode=0),
            # git checkout feature
            MagicMock(returncode=0),
            # git add -A
            MagicMock(returncode=0),
            # git status --porcelain
            MagicMock(returncode=0, stdout="M file.txt\n"),
            # git commit
            MagicMock(returncode=0),
            # _delete_conflicting_remote_refs: git ls-remote --heads origin
            MagicMock(returncode=0, stdout=""),
            # git push origin HEAD:refs/heads/feature
            MagicMock(returncode=0),
        ]

        req = ActionRequest(
            capability="git_commit_and_push",
            params={
                "commit_message": "update",
                "branch": "feature",
            },
            resolved_write_dirs=[str(tmp_path)],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REMOTE_URL = ""
            result = git_commit_and_push(req)

        assert result.status == ActionStatus.SUCCESS
        calls = [c[0][0] for c in mock_git.call_args_list]
        assert ["checkout", "feature"] in calls


# ═══════════════════════════════════════════════════════════════════════
# git_clone_repo: PathGuard denial
# ═══════════════════════════════════════════════════════════════════════

class TestGitCloneRepoPathGuard:
    def test_pathguard_denied(self, tmp_path):
        """Clone is denied when repo path is outside allowed write dirs."""
        repo_path = tmp_path / "workspace"
        req = ActionRequest(
            capability="git_clone_repo",
            params={},
            resolved_write_dirs=["/some/unrelated/dir"],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REMOTE_URL = "https://github.com/test/repo.git"
            mock_cfg.GIT_LOCAL_REPO_PATH = str(repo_path)
            result = git_clone_repo(req)

        assert result.status == ActionStatus.FAILED
        assert "PathGuard" in result.detail


# ═══════════════════════════════════════════════════════════════════════
# git_commit_and_push: PathGuard denial
# ═══════════════════════════════════════════════════════════════════════

class TestGitCommitAndPushPathGuard:
    def test_pathguard_denied(self, tmp_path):
        """Commit is denied when repo path is outside allowed write dirs."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        req = ActionRequest(
            capability="git_commit_and_push",
            params={"commit_message": "test"},
            resolved_write_dirs=["/some/unrelated/dir"],
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_LOCAL_REPO_PATH = str(tmp_path)
            mock_cfg.GIT_FORK_OWNER = ""
            result = git_commit_and_push(req)

        assert result.status == ActionStatus.FAILED
        assert "PathGuard" in result.detail


# ═══════════════════════════════════════════════════════════════════════
# create_github_pr: missing repo config
# ═══════════════════════════════════════════════════════════════════════

class TestCreateGitHubPrMissingConfig:
    def test_missing_repo_config(self):
        """PR creation fails when repo_owner/repo_name are not set."""
        req = ActionRequest(
            capability="create_github_pr",
            params={
                "title": "PR",
                "head_branch": "branch",
            },
        )
        with patch("src.executor.handlers.git_ops.config") as mock_cfg:
            mock_cfg.GIT_TOKEN = "fake-token"
            mock_cfg.GIT_FORK_OWNER = ""
            mock_cfg.GIT_REPO_OWNER = ""
            mock_cfg.GIT_REPO_NAME = ""
            result = create_github_pr(req)

        assert result.status == ActionStatus.FAILED
        assert "repo_owner" in result.detail or "repo_name" in result.detail
