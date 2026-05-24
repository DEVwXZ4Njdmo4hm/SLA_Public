#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_executor.py
Description:  Tests for executor models, registry, path guard, policy, and runtime.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import json
import textwrap
import time
from pathlib import Path

import pytest

from src.executor.models import (
    ActionRequest,
    ActionStatus,
    AuditEntry,
    AuditLevel,
    Capability,
    ExecutionResult,
    ParamConstraint,
    PathAccess,
    PolicyDecision,
    RateLimit,
)
from src.executor.registry import CapabilityRegistry
from src.executor.path_guard import PathGuard
from src.executor.path_guard import check_write_path
from src.executor.policy import PolicyEngine
from src.executor.audit import AuditDB
from src.executor.runtime import ExecutorRuntime
from src.executor.handlers import HandlerRegistry
from src.executor import build_executor


# ═══════════════════════════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════════════════════════

class TestModels:
    def test_action_status_values(self):
        assert ActionStatus.PENDING.value == "pending"
        assert ActionStatus.DRY_RUN.value == "dry_run"
        assert ActionStatus.SUCCESS.value == "success"

    def test_capability_defaults(self):
        cap = Capability(name="test")
        assert cap.enabled is True
        assert cap.allowed_roles == []
        assert cap.params == []
        assert cap.rate_limit is None

    def test_action_request_defaults(self):
        req = ActionRequest(capability="foo")
        assert req.actor_role == "Agent"
        assert req.params == {}

    def test_execution_result(self):
        r = ExecutionResult(
            request_id="abc", capability="foo",
            status=ActionStatus.SUCCESS, detail="ok",
        )
        assert r.status == ActionStatus.SUCCESS

    def test_audit_entry_fields(self):
        e = AuditEntry(
            request_id="r1", capability="c1",
            actor_role="Agent", actor_id="llm",
            status="success",
        )
        assert e.level == "info"


# ═══════════════════════════════════════════════════════════════════════
# CapabilityRegistry
# ═══════════════════════════════════════════════════════════════════════

class TestCapabilityRegistry:
    def test_manual_register_and_get(self):
        reg = CapabilityRegistry()
        cap = Capability(name="test_cap", handler="h1")
        reg.register(cap)
        assert "test_cap" in reg
        assert reg.get("test_cap") is cap
        assert len(reg) == 1
        assert reg.list_names() == ["test_cap"]

    def test_get_missing_returns_none(self):
        reg = CapabilityRegistry()
        assert reg.get("nonexistent") is None

    def test_load_file(self, tmp_path: Path):
        toml_content = textwrap.dedent("""\
            [capability.rule_suggest]
            description = "Suggest a rule"
            handler = "rule_handler"
            allowed_roles = ["Agent", "Owner"]
            enabled = true

            [capability.rule_suggest.params.rule_text]
            type = "string"
            required = true
            pattern = "^alert .+"

            [capability.rule_suggest.params.priority]
            type = "integer"
            required = false
            min = 1
            max = 10

            [capability.rule_suggest.rate_limit]
            max_calls = 5
            window_seconds = 60
        """)
        toml_file = tmp_path / "caps.toml"
        toml_file.write_text(toml_content)

        reg = CapabilityRegistry()
        loaded = reg.load_file(toml_file)
        assert loaded == 1

        cap = reg.get("rule_suggest")
        assert cap is not None
        assert cap.handler == "rule_handler"
        assert cap.allowed_roles == ["Agent", "Owner"]
        assert len(cap.params) == 2
        assert cap.params[0].name == "rule_text"
        assert cap.params[0].pattern == "^alert .+"
        assert cap.params[1].min_value == 1
        assert cap.params[1].max_value == 10
        assert cap.rate_limit is not None
        assert cap.rate_limit.max_calls == 5

    def test_load_dir(self, tmp_path: Path):
        (tmp_path / "a.toml").write_text(
            '[capability.alpha]\ndescription = "A"\nhandler = "a"\n'
        )
        (tmp_path / "b.toml").write_text(
            '[capability.beta]\ndescription = "B"\nhandler = "b"\n'
        )
        reg = CapabilityRegistry()
        assert reg.load_dir(tmp_path) == 2
        assert len(reg) == 2

    def test_load_dir_nonexistent(self, tmp_path: Path):
        reg = CapabilityRegistry()
        assert reg.load_dir(tmp_path / "nope") == 0

    def test_load_bad_toml_skipped(self, tmp_path: Path):
        (tmp_path / "bad.toml").write_text("not = [valid toml {{{")
        reg = CapabilityRegistry()
        assert reg.load_dir(tmp_path) == 0

    def test_paths_parsing(self, tmp_path: Path):
        toml_content = textwrap.dedent("""\
            [capability.file_op]
            handler = "file_handler"

            [capability.file_op.paths.read]
            dirs = ["/app/rules"]

            [capability.file_op.paths.write]
            dirs = ["/app/rules", "/tmp"]
        """)
        (tmp_path / "paths.toml").write_text(toml_content)
        reg = CapabilityRegistry()
        reg.load_dir(tmp_path)
        cap = reg.get("file_op")
        assert cap is not None
        assert PathAccess.READ in cap.paths
        assert "/app/rules" in cap.paths[PathAccess.READ]
        assert len(cap.paths[PathAccess.WRITE]) == 2


# ═══════════════════════════════════════════════════════════════════════
# PathGuard
# ═══════════════════════════════════════════════════════════════════════

class TestPathGuard:
    def test_no_sandbox_allows_within_allowed_dir(self, tmp_path: Path):
        guard = PathGuard(sandbox_root=None)
        target = tmp_path / "data" / "file.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch()
        assert guard.check(str(target), [str(tmp_path)]) is True

    def test_no_allowed_dirs_rejects(self, tmp_path: Path):
        guard = PathGuard(sandbox_root=None)
        assert guard.check(str(tmp_path / "f.txt"), []) is False

    def test_sandbox_rejects_outside(self, tmp_path: Path):
        sandbox = tmp_path / "sandbox"
        sandbox.mkdir()
        guard = PathGuard(sandbox_root=str(sandbox))
        outside = tmp_path / "outside" / "file.txt"
        assert guard.check(str(outside), [str(tmp_path)]) is False

    def test_sandbox_accepts_inside(self, tmp_path: Path):
        sandbox = tmp_path / "sandbox"
        inner = sandbox / "data"
        inner.mkdir(parents=True)
        guard = PathGuard(sandbox_root=str(sandbox))
        assert guard.check(str(inner / "f.txt"), [str(sandbox)]) is True

    def test_path_traversal_blocked(self, tmp_path: Path):
        sandbox = tmp_path / "sandbox"
        sandbox.mkdir()
        guard = PathGuard(sandbox_root=str(sandbox))
        traversal = str(sandbox / ".." / "outside")
        assert guard.check(traversal, [str(sandbox)]) is False

    def test_sandbox_root_property(self, tmp_path: Path):
        guard = PathGuard(str(tmp_path))
        assert guard.sandbox_root is not None
        guard2 = PathGuard(None)
        assert guard2.sandbox_root is None


# ═══════════════════════════════════════════════════════════════════════
# check_write_path standalone utility
# ═══════════════════════════════════════════════════════════════════════

class TestCheckWritePath:
    def test_allowed(self, tmp_path: Path):
        target = str(tmp_path / "sub" / "file.txt")
        assert check_write_path(target, [str(tmp_path)]) is None

    def test_empty_dirs_rejected(self, tmp_path: Path):
        err = check_write_path(str(tmp_path / "f.txt"), [])
        assert err is not None
        assert "No write directories" in err

    def test_outside_rejected(self, tmp_path: Path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        target = str(tmp_path / "other" / "f.txt")
        err = check_write_path(target, [str(allowed)])
        assert err is not None
        assert "outside" in err

    def test_traversal_rejected(self, tmp_path: Path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        target = str(allowed / ".." / "outside" / "f.txt")
        err = check_write_path(target, [str(allowed)])
        assert err is not None

    def test_multiple_dirs_first_match(self, tmp_path: Path):
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()
        assert check_write_path(str(dir_b / "f.txt"), [str(dir_a), str(dir_b)]) is None


# ═══════════════════════════════════════════════════════════════════════
# CapabilityRegistry — variable expansion
# ═══════════════════════════════════════════════════════════════════════

class TestRegistryVariableExpansion:
    def test_path_vars_expanded(self, tmp_path: Path):
        toml_content = textwrap.dedent("""\
            [capability.write_op]
            handler = "h"

            [capability.write_op.paths.write]
            dirs = ["{repo_dir}/rules"]
        """)
        (tmp_path / "vars.toml").write_text(toml_content)
        reg = CapabilityRegistry()
        reg.load_dir(tmp_path, path_vars={"repo_dir": "/app/git"})
        cap = reg.get("write_op")
        assert cap is not None
        assert "/app/git/rules" in cap.paths[PathAccess.WRITE]

    def test_no_vars_leaves_literal(self, tmp_path: Path):
        toml_content = textwrap.dedent("""\
            [capability.op]
            handler = "h"

            [capability.op.paths.write]
            dirs = ["/static/path"]
        """)
        (tmp_path / "static.toml").write_text(toml_content)
        reg = CapabilityRegistry()
        reg.load_dir(tmp_path)
        cap = reg.get("op")
        assert "/static/path" in cap.paths[PathAccess.WRITE]

    def test_unknown_var_kept_raw(self, tmp_path: Path):
        toml_content = textwrap.dedent("""\
            [capability.bad]
            handler = "h"

            [capability.bad.paths.write]
            dirs = ["{undefined_var}/data"]
        """)
        (tmp_path / "bad.toml").write_text(toml_content)
        reg = CapabilityRegistry()
        reg.load_dir(tmp_path, path_vars={"repo_dir": "/app"})
        cap = reg.get("bad")
        assert cap is not None
        # Unresolvable var is kept as raw string (with warning logged)
        assert "{undefined_var}/data" in cap.paths[PathAccess.WRITE]


# ═══════════════════════════════════════════════════════════════════════
# Capability — path_params field
# ═══════════════════════════════════════════════════════════════════════

class TestCapabilityPathParams:
    def test_default_empty(self):
        cap = Capability(name="t")
        assert cap.path_params == []

    def test_path_params_from_toml(self, tmp_path: Path):
        toml_content = textwrap.dedent("""\
            [capability.file_op]
            handler = "h"
            path_params = ["output_path", "target_dir"]
        """)
        (tmp_path / "pp.toml").write_text(toml_content)
        reg = CapabilityRegistry()
        reg.load_dir(tmp_path)
        cap = reg.get("file_op")
        assert cap is not None
        assert cap.path_params == ["output_path", "target_dir"]


# ═══════════════════════════════════════════════════════════════════════
# ExecutorRuntime — resolved_write_dirs injection
# ═══════════════════════════════════════════════════════════════════════

class TestRuntimeResolvedWriteDirs:
    def test_write_dirs_injected(self, tmp_path: Path):
        """Runtime should populate resolved_write_dirs before handler dispatch."""
        captured_dirs = []

        def capture_handler(req: ActionRequest) -> ExecutionResult:
            captured_dirs.extend(req.resolved_write_dirs)
            return ExecutionResult(
                request_id=req.request_id, capability=req.capability,
                status=ActionStatus.SUCCESS, detail="ok",
            )

        write_dir = str(tmp_path / "output")
        registry = CapabilityRegistry()
        cap = Capability(
            name="writer", handler="cap_handler",
            paths={PathAccess.WRITE: [write_dir]},
        )
        registry.register(cap)

        handlers = HandlerRegistry()
        handlers.register("cap_handler", capture_handler)

        runtime = ExecutorRuntime(
            registry=registry,
            policy=PolicyEngine(),
            path_guard=PathGuard(None),
            handler_registry=handlers,
        )
        req = ActionRequest(capability="writer", params={}, actor_role="Agent")
        result = runtime.execute(req)
        assert result.status == ActionStatus.SUCCESS
        assert write_dir in captured_dirs

    def test_no_write_paths_empty_dirs(self, tmp_path: Path):
        """Capabilities without paths.write should give empty resolved_write_dirs."""
        captured_dirs = []

        def capture_handler(req: ActionRequest) -> ExecutionResult:
            captured_dirs.extend(req.resolved_write_dirs)
            return ExecutionResult(
                request_id=req.request_id, capability=req.capability,
                status=ActionStatus.SUCCESS, detail="ok",
            )

        registry = CapabilityRegistry()
        cap = Capability(name="reader", handler="cap_handler")
        registry.register(cap)

        handlers = HandlerRegistry()
        handlers.register("cap_handler", capture_handler)

        runtime = ExecutorRuntime(
            registry=registry,
            policy=PolicyEngine(),
            path_guard=PathGuard(None),
            handler_registry=handlers,
        )
        req = ActionRequest(capability="reader", params={}, actor_role="Agent")
        result = runtime.execute(req)
        assert result.status == ActionStatus.SUCCESS
        assert captured_dirs == []


# ═══════════════════════════════════════════════════════════════════════
# PolicyEngine
# ═══════════════════════════════════════════════════════════════════════

class TestPolicyEngine:
    @pytest.fixture
    def engine(self):
        return PolicyEngine()

    @pytest.fixture
    def cap(self):
        return Capability(
            name="test_cap",
            handler="handler",
            allowed_roles=["Agent", "Owner"],
            params=[
                ParamConstraint(name="text", type="string", required=True, pattern=r"^alert .+"),
                ParamConstraint(name="priority", type="integer", required=False, min_value=1, max_value=10),
            ],
            rate_limit=RateLimit(max_calls=3, window_seconds=60),
        )

    def test_approve_valid(self, engine: PolicyEngine, cap: Capability):
        d = engine.evaluate(cap, "Agent", "user1", {"text": "alert tcp any any -> any any"})
        assert d.allowed is True

    def test_reject_wrong_role(self, engine: PolicyEngine, cap: Capability):
        d = engine.evaluate(cap, "Watcher", "user2", {"text": "alert tcp"})
        assert d.allowed is False
        assert "Role" in d.reason

    def test_reject_missing_required_param(self, engine: PolicyEngine, cap: Capability):
        d = engine.evaluate(cap, "Agent", "user1", {})
        assert d.allowed is False
        assert "Missing required" in d.reason

    def test_reject_unknown_param(self, engine: PolicyEngine, cap: Capability):
        d = engine.evaluate(cap, "Agent", "user1", {"text": "alert x", "unknown": 42})
        assert d.allowed is False
        assert "Unknown parameter" in d.reason

    def test_reject_pattern_mismatch(self, engine: PolicyEngine, cap: Capability):
        d = engine.evaluate(cap, "Agent", "user1", {"text": "drop tcp"})
        assert d.allowed is False
        assert "pattern" in d.reason

    def test_reject_integer_out_of_range(self, engine: PolicyEngine, cap: Capability):
        d = engine.evaluate(cap, "Agent", "user1", {"text": "alert x", "priority": 99})
        assert d.allowed is False
        assert "exceeds" in d.reason

    def test_reject_integer_below_min(self, engine: PolicyEngine, cap: Capability):
        d = engine.evaluate(cap, "Agent", "user1", {"text": "alert x", "priority": 0})
        assert d.allowed is False
        assert "below" in d.reason

    def test_reject_wrong_type_string(self, engine: PolicyEngine, cap: Capability):
        d = engine.evaluate(cap, "Agent", "user1", {"text": 123})
        assert d.allowed is False
        assert "string" in d.reason

    def test_reject_wrong_type_integer(self, engine: PolicyEngine, cap: Capability):
        d = engine.evaluate(cap, "Agent", "user1", {"text": "alert x", "priority": "high"})
        assert d.allowed is False
        assert "integer" in d.reason

    def test_reject_boolean_type(self, engine: PolicyEngine):
        cap = Capability(
            name="bool_test", handler="h",
            params=[ParamConstraint(name="flag", type="boolean", required=True)],
        )
        d = engine.evaluate(cap, "Agent", "u", {"flag": "yes"})
        assert d.allowed is False

    def test_approve_boolean_type(self, engine: PolicyEngine):
        cap = Capability(
            name="bool_test", handler="h",
            params=[ParamConstraint(name="flag", type="boolean", required=True)],
        )
        d = engine.evaluate(cap, "Agent", "u", {"flag": True})
        assert d.allowed is True

    def test_choices_constraint(self, engine: PolicyEngine):
        cap = Capability(
            name="choice_test", handler="h",
            params=[ParamConstraint(name="color", type="string", choices=["red", "blue"])],
        )
        assert engine.evaluate(cap, "Agent", "u", {"color": "red"}).allowed is True
        assert engine.evaluate(cap, "Agent", "u", {"color": "green"}).allowed is False

    def test_disabled_capability(self, engine: PolicyEngine):
        cap = Capability(name="disabled", handler="h", enabled=False)
        d = engine.evaluate(cap, "Agent", "u", {})
        assert d.allowed is False
        assert "disabled" in d.reason

    def test_rate_limit(self, engine: PolicyEngine, cap: Capability):
        # cap has rate_limit = 3 calls per 60s
        for _ in range(3):
            d = engine.evaluate(cap, "Agent", "user1", {"text": "alert x"})
            assert d.allowed is True
        d = engine.evaluate(cap, "Agent", "user1", {"text": "alert x"})
        assert d.allowed is False
        assert "Rate limit" in d.reason

    def test_rate_limit_different_actors_independent(self, engine: PolicyEngine, cap: Capability):
        for _ in range(3):
            engine.evaluate(cap, "Agent", "user1", {"text": "alert x"})
        # user2 should still be allowed
        d = engine.evaluate(cap, "Agent", "user2", {"text": "alert x"})
        assert d.allowed is True

    def test_no_role_restriction_passes(self, engine: PolicyEngine):
        cap = Capability(name="open", handler="h", allowed_roles=[])
        d = engine.evaluate(cap, "Anyone", "u", {})
        assert d.allowed is True

    def test_float_param_validation(self, engine: PolicyEngine):
        cap = Capability(
            name="float_test", handler="h",
            params=[ParamConstraint(name="score", type="float", min_value=0.0, max_value=1.0)],
        )
        assert engine.evaluate(cap, "Agent", "u", {"score": 0.5}).allowed is True
        assert engine.evaluate(cap, "Agent", "u", {"score": 1.5}).allowed is False
        assert engine.evaluate(cap, "Agent", "u", {"score": "abc"}).allowed is False


# ═══════════════════════════════════════════════════════════════════════
# AuditDB
# ═══════════════════════════════════════════════════════════════════════

class TestAuditDB:
    @pytest.fixture
    def db(self, tmp_path: Path) -> AuditDB:
        return AuditDB(tmp_path / "test_audit.db")

    def _make_entry(self, **overrides) -> AuditEntry:
        defaults = dict(
            request_id="req-1",
            capability="test_cap",
            actor_role="Agent",
            actor_id="llm",
            status="success",
            detail="ok",
            params_json='{"text": "alert x"}',
            level="info",
        )
        defaults.update(overrides)
        return AuditEntry(**defaults)

    def test_record_and_count(self, db: AuditDB):
        entry = self._make_entry()
        row_id = db.record(entry)
        assert row_id > 0
        assert db.count() == 1

    def test_list_recent(self, db: AuditDB):
        db.record(self._make_entry(request_id="r1"))
        db.record(self._make_entry(request_id="r2"))
        db.record(self._make_entry(request_id="r3"))
        entries = db.list_recent(2)
        assert len(entries) == 2
        # Newest first
        assert entries[0].request_id == "r3"
        assert entries[1].request_id == "r2"

    def test_list_by_capability(self, db: AuditDB):
        db.record(self._make_entry(capability="a"))
        db.record(self._make_entry(capability="b"))
        db.record(self._make_entry(capability="a"))
        entries = db.list_by_capability("a")
        assert len(entries) == 2
        assert all(e.capability == "a" for e in entries)

    def test_list_by_actor(self, db: AuditDB):
        db.record(self._make_entry(actor_id="llm"))
        db.record(self._make_entry(actor_id="human"))
        entries = db.list_by_actor("llm")
        assert len(entries) == 1

    def test_get_by_request_id(self, db: AuditDB):
        db.record(self._make_entry(request_id="unique-123"))
        entry = db.get_by_request_id("unique-123")
        assert entry is not None
        assert entry.request_id == "unique-123"

    def test_get_missing_request_id(self, db: AuditDB):
        assert db.get_by_request_id("nope") is None

    def test_close_is_noop(self, db: AuditDB):
        db.close()  # should not raise


# ═══════════════════════════════════════════════════════════════════════
# ExecutorRuntime
# ═══════════════════════════════════════════════════════════════════════

class TestExecutorRuntime:
    @pytest.fixture
    def setup(self, tmp_path: Path):
        """Create a fully wired executor runtime with one test capability."""
        registry = CapabilityRegistry()
        cap = Capability(
            name="greet",
            handler="greet_handler",
            allowed_roles=["Agent", "Owner"],
            params=[
                ParamConstraint(name="name", type="string", required=True),
            ],
        )
        registry.register(cap)

        handlers = HandlerRegistry()

        def greet_handler(req: ActionRequest) -> ExecutionResult:
            return ExecutionResult(
                request_id=req.request_id,
                capability=req.capability,
                status=ActionStatus.SUCCESS,
                detail=f"Hello, {req.params['name']}!",
                output={"greeting": f"Hello, {req.params['name']}!"},
            )
        handlers.register("greet_handler", greet_handler)

        audit_db = AuditDB(tmp_path / "audit.db")

        runtime = ExecutorRuntime(
            registry=registry,
            policy=PolicyEngine(),
            path_guard=PathGuard(None),
            audit_db=audit_db,
            handler_registry=handlers,
            dry_run=False,
        )
        return runtime, audit_db

    def test_execute_success(self, setup):
        runtime, audit_db = setup
        req = ActionRequest(capability="greet", params={"name": "World"}, actor_role="Agent")
        result = runtime.execute(req)
        assert result.status == ActionStatus.SUCCESS
        assert "Hello, World!" in result.detail
        assert audit_db.count() == 1

    def test_execute_unknown_capability(self, setup):
        runtime, audit_db = setup
        req = ActionRequest(capability="nonexistent", params={}, actor_role="Agent")
        result = runtime.execute(req)
        assert result.status == ActionStatus.REJECTED
        assert "Unknown capability" in result.detail

    def test_execute_role_denied(self, setup):
        runtime, _ = setup
        req = ActionRequest(capability="greet", params={"name": "X"}, actor_role="Watcher")
        result = runtime.execute(req)
        assert result.status == ActionStatus.REJECTED
        assert "Role" in result.detail

    def test_execute_missing_param(self, setup):
        runtime, _ = setup
        req = ActionRequest(capability="greet", params={}, actor_role="Agent")
        result = runtime.execute(req)
        assert result.status == ActionStatus.REJECTED
        assert "Missing required" in result.detail

    def test_dry_run_mode(self, setup):
        runtime, audit_db = setup
        runtime.dry_run = True
        req = ActionRequest(capability="greet", params={"name": "Test"}, actor_role="Agent")
        result = runtime.execute(req)
        assert result.status == ActionStatus.DRY_RUN
        assert audit_db.count() == 1
        entry = audit_db.list_recent(1)[0]
        assert entry.status == "dry_run"

    def test_request_id_auto_assigned(self, setup):
        runtime, _ = setup
        req = ActionRequest(capability="greet", params={"name": "X"}, actor_role="Agent")
        assert req.request_id == ""
        result = runtime.execute(req)
        assert result.request_id != ""

    def test_handler_exception_returns_failed(self, tmp_path: Path):
        registry = CapabilityRegistry()
        registry.register(Capability(name="boom", handler="boom_handler"))
        handlers = HandlerRegistry()

        def boom_handler(req):
            raise RuntimeError("Kaboom!")
        handlers.register("boom_handler", boom_handler)

        runtime = ExecutorRuntime(
            registry=registry,
            policy=PolicyEngine(),
            path_guard=PathGuard(None),
            handler_registry=handlers,
        )
        req = ActionRequest(capability="boom", params={}, actor_role="Agent")
        result = runtime.execute(req)
        assert result.status == ActionStatus.FAILED
        assert "Kaboom!" in result.detail

    def test_no_handler_registered(self, tmp_path: Path):
        registry = CapabilityRegistry()
        registry.register(Capability(name="orphan", handler="missing_handler"))
        runtime = ExecutorRuntime(
            registry=registry,
            policy=PolicyEngine(),
            path_guard=PathGuard(None),
            handler_registry=HandlerRegistry(),
        )
        req = ActionRequest(capability="orphan", params={}, actor_role="Agent")
        result = runtime.execute(req)
        assert result.status == ActionStatus.REJECTED
        assert "No handler" in result.detail


# ═══════════════════════════════════════════════════════════════════════
# build_executor factory
# ═══════════════════════════════════════════════════════════════════════

class TestBuildExecutor:
    def test_build_with_capabilities_dir(self, tmp_path: Path):
        cap_dir = tmp_path / "caps"
        cap_dir.mkdir()
        (cap_dir / "test.toml").write_text(
            '[capability.ping]\ndescription = "Ping"\nhandler = "ping"\n'
        )
        executor = build_executor(
            capabilities_dir=str(cap_dir),
            audit_db_path=str(tmp_path / "audit.db"),
            dry_run=True,
        )
        assert "ping" in executor.registry
        assert executor.dry_run is True
        assert executor.audit_db is not None

    def test_build_empty_dir(self, tmp_path: Path):
        executor = build_executor(capabilities_dir="", audit_db_path="")
        assert len(executor.registry) == 0
        assert executor.audit_db is None

    def test_build_nonexistent_dir(self, tmp_path: Path):
        executor = build_executor(
            capabilities_dir=str(tmp_path / "nonexistent"),
        )
        assert len(executor.registry) == 0


# ═══════════════════════════════════════════════════════════════════════
# HandlerRegistry
# ═══════════════════════════════════════════════════════════════════════

class TestHandlerRegistry:
    def test_register_and_get(self):
        reg = HandlerRegistry()
        def dummy(req): ...
        reg.register("test", dummy)
        assert reg.get("test") is dummy
        assert "test" in reg
        assert reg.list_names() == ["test"]

    def test_get_missing(self):
        reg = HandlerRegistry()
        assert reg.get("nope") is None
        assert "nope" not in reg


# ═══════════════════════════════════════════════════════════════════════
# PolicyEngine — U-A-P identity verification
# ═══════════════════════════════════════════════════════════════════════

class TestPolicyEngineIdentity:
    """Tests for the _check_identity stage that verifies actor_id against
    the U-A-P user database."""

    @pytest.fixture
    def user_db(self, tmp_path: Path):
        from src.auth.database import UserDB
        return UserDB(tmp_path / "policy_uap.db")

    @pytest.fixture
    def agent_user(self, user_db):
        from src.auth.models import Role
        return user_db.create_user("suricata-analyzer-agent", "agent@localhost", "pw123456", Role.AGENT)

    def test_no_db_allows_any(self):
        """Without user_db, identity check is a no-op (backward compat)."""
        engine = PolicyEngine(user_db=None)
        cap = Capability(name="t", handler="h", allowed_roles=["Agent"])
        d = engine.evaluate(cap, "Agent", "llm", {})
        assert d.allowed is True

    def test_valid_actor_passes(self, user_db, agent_user):
        engine = PolicyEngine(user_db=user_db)
        cap = Capability(name="t", handler="h", allowed_roles=["Agent"])
        d = engine.evaluate(cap, "Agent", str(agent_user.id), {})
        assert d.allowed is True

    def test_empty_actor_id_rejected(self, user_db, agent_user):
        engine = PolicyEngine(user_db=user_db)
        cap = Capability(name="t", handler="h", allowed_roles=["Agent"])
        d = engine.evaluate(cap, "Agent", "", {})
        assert d.allowed is False
        assert "actor_id is required" in d.reason

    def test_nonexistent_actor_id_rejected(self, user_db, agent_user):
        engine = PolicyEngine(user_db=user_db)
        cap = Capability(name="t", handler="h", allowed_roles=["Agent"])
        d = engine.evaluate(cap, "Agent", "99999", {})
        assert d.allowed is False
        assert "No user found" in d.reason

    def test_role_mismatch_rejected(self, user_db, agent_user):
        """Actor exists but claims a role different from their DB record."""
        engine = PolicyEngine(user_db=user_db)
        cap = Capability(name="t", handler="h", allowed_roles=["Owner", "Agent"])
        d = engine.evaluate(cap, "Owner", str(agent_user.id), {})
        assert d.allowed is False
        assert "Role mismatch" in d.reason

    def test_non_numeric_actor_id_rejected(self, user_db, agent_user):
        engine = PolicyEngine(user_db=user_db)
        cap = Capability(name="t", handler="h", allowed_roles=["Agent"])
        d = engine.evaluate(cap, "Agent", "not-a-number", {})
        assert d.allowed is False
        assert "not a valid user identifier" in d.reason


# ═══════════════════════════════════════════════════════════════════════
# ExecutorRuntime — API key verification
# ═══════════════════════════════════════════════════════════════════════

class TestRuntimeAPIKeyVerification:
    """Tests for the API key verification step in ExecutorRuntime.execute()."""

    @pytest.fixture
    def wired_runtime(self, tmp_path: Path):
        from src.auth.database import UserDB
        from src.auth.models import Role
        from src.auth.tokens import generate_api_key

        user_db = UserDB(tmp_path / "rt_uap.db")
        agent = user_db.create_user("suricata-analyzer-agent", "agent@localhost", "pw123456", Role.AGENT)
        raw_key = generate_api_key()
        user_db.create_api_key(agent.id, raw_key, label="test")

        registry = CapabilityRegistry()
        cap = Capability(name="ping", handler="ping_h", allowed_roles=["Agent"])
        registry.register(cap)

        handlers = HandlerRegistry()
        def ping_h(req):
            return ExecutionResult(
                request_id=req.request_id, capability=req.capability,
                status=ActionStatus.SUCCESS, detail="pong",
            )
        handlers.register("ping_h", ping_h)

        runtime = ExecutorRuntime(
            registry=registry,
            policy=PolicyEngine(user_db=user_db),
            path_guard=PathGuard(None),
            handler_registry=handlers,
            user_db=user_db,
        )
        return runtime, agent, raw_key

    def test_valid_api_key_passes(self, wired_runtime):
        runtime, agent, raw_key = wired_runtime
        req = ActionRequest(
            capability="ping", params={},
            actor_role="Agent", actor_id=str(agent.id), api_key=raw_key,
        )
        result = runtime.execute(req)
        assert result.status == ActionStatus.SUCCESS

    def test_invalid_api_key_rejected(self, wired_runtime):
        runtime, agent, _ = wired_runtime
        req = ActionRequest(
            capability="ping", params={},
            actor_role="Agent", actor_id=str(agent.id), api_key="bad-key",
        )
        result = runtime.execute(req)
        assert result.status == ActionStatus.REJECTED
        assert "Invalid or revoked" in result.detail

    def test_api_key_wrong_user_rejected(self, wired_runtime):
        runtime, agent, raw_key = wired_runtime
        req = ActionRequest(
            capability="ping", params={},
            actor_role="Agent", actor_id="99999", api_key=raw_key,
        )
        result = runtime.execute(req)
        assert result.status == ActionStatus.REJECTED

    def test_no_api_key_skips_verification(self, wired_runtime):
        """When api_key is empty, key verification is skipped
        (identity is still checked by policy engine)."""
        runtime, agent, _ = wired_runtime
        req = ActionRequest(
            capability="ping", params={},
            actor_role="Agent", actor_id=str(agent.id), api_key="",
        )
        result = runtime.execute(req)
        assert result.status == ActionStatus.SUCCESS

    def test_no_user_db_skips_all_verification(self, tmp_path: Path):
        """Without user_db, both identity and API key checks are skipped."""
        registry = CapabilityRegistry()
        cap = Capability(name="ping", handler="ping_h", allowed_roles=["Agent"])
        registry.register(cap)
        handlers = HandlerRegistry()
        def ping_h(req):
            return ExecutionResult(
                request_id=req.request_id, capability=req.capability,
                status=ActionStatus.SUCCESS, detail="pong",
            )
        handlers.register("ping_h", ping_h)

        runtime = ExecutorRuntime(
            registry=registry,
            policy=PolicyEngine(),
            path_guard=PathGuard(None),
            handler_registry=handlers,
        )
        req = ActionRequest(
            capability="ping", params={},
            actor_role="Agent", actor_id="llm",
        )
        result = runtime.execute(req)
        assert result.status == ActionStatus.SUCCESS
