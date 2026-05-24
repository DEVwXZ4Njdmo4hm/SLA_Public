#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_tool_schema.py
Description:  Tests for capability to JSON Schema conversion for tool definitions.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import pytest

from src.executor.models import Capability, ParamConstraint, RateLimit
from src.executor.registry import CapabilityRegistry
from src.tool_schema import capability_to_tool, capabilities_to_tools, _param_to_json_schema


# ---------------------------------------------------------------------------
# _param_to_json_schema
# ---------------------------------------------------------------------------

class TestParamToJsonSchema:
    def test_string_type(self):
        p = ParamConstraint(name="title", type="string")
        schema = _param_to_json_schema(p)
        assert schema["type"] == "string"

    def test_integer_type(self):
        p = ParamConstraint(name="priority", type="integer")
        schema = _param_to_json_schema(p)
        assert schema["type"] == "integer"

    def test_float_type(self):
        p = ParamConstraint(name="score", type="float")
        schema = _param_to_json_schema(p)
        assert schema["type"] == "number"

    def test_boolean_type(self):
        p = ParamConstraint(name="enabled", type="boolean")
        schema = _param_to_json_schema(p)
        assert schema["type"] == "boolean"

    def test_choices_become_enum(self):
        p = ParamConstraint(name="severity", type="string", choices=["low", "high"])
        schema = _param_to_json_schema(p)
        assert schema["enum"] == ["low", "high"]

    def test_pattern_omitted(self):
        p = ParamConstraint(name="rule_text", type="string", pattern=r"^alert .+")
        schema = _param_to_json_schema(p)
        assert "pattern" not in schema

    def test_unknown_type_defaults_to_string(self):
        p = ParamConstraint(name="x", type="exotic")
        schema = _param_to_json_schema(p)
        assert schema["type"] == "string"


# ---------------------------------------------------------------------------
# capability_to_tool
# ---------------------------------------------------------------------------

class TestCapabilityToTool:
    def test_basic_shape(self):
        cap = Capability(
            name="create_github_issue",
            description="Create an issue",
            handler="create_github_issue",
            allowed_roles=["Agent"],
            params=[
                ParamConstraint(name="title", type="string", required=True),
                ParamConstraint(name="body", type="string", required=True),
                ParamConstraint(name="labels", type="string", required=False),
            ],
        )
        tool = capability_to_tool(cap)
        assert tool["type"] == "function"
        func = tool["function"]
        assert func["name"] == "create_github_issue"
        assert func["description"] == "Create an issue"
        params = func["parameters"]
        assert params["type"] == "object"
        assert "title" in params["properties"]
        assert "body" in params["properties"]
        assert "labels" in params["properties"]
        assert params["required"] == ["title", "body"]

    def test_empty_description_uses_fallback(self):
        cap = Capability(name="my_action", handler="h")
        tool = capability_to_tool(cap)
        assert "my_action" in tool["function"]["description"]

    def test_no_required_params(self):
        cap = Capability(
            name="reset",
            handler="h",
            params=[ParamConstraint(name="force", type="boolean", required=False)],
        )
        tool = capability_to_tool(cap)
        assert "required" not in tool["function"]["parameters"]


# ---------------------------------------------------------------------------
# capabilities_to_tools — registry integration
# ---------------------------------------------------------------------------

class TestCapabilitiesToTools:
    def _make_registry(self) -> CapabilityRegistry:
        reg = CapabilityRegistry()
        reg.register(Capability(
            name="action_a",
            handler="a",
            allowed_roles=["Agent"],
            enabled=True,
        ))
        reg.register(Capability(
            name="action_b",
            handler="b",
            allowed_roles=["Owner"],
            enabled=True,
        ))
        reg.register(Capability(
            name="action_c",
            handler="c",
            allowed_roles=["Agent", "Owner"],
            enabled=False,
        ))
        return reg

    def test_filters_by_role(self):
        reg = self._make_registry()
        tools = capabilities_to_tools(reg, actor_role="Agent")
        names = [t["function"]["name"] for t in tools]
        assert "action_a" in names
        assert "action_b" not in names  # Owner only

    def test_excludes_disabled(self):
        reg = self._make_registry()
        tools = capabilities_to_tools(reg, actor_role="Agent")
        names = [t["function"]["name"] for t in tools]
        assert "action_c" not in names

    def test_empty_registry(self):
        reg = CapabilityRegistry()
        assert capabilities_to_tools(reg, actor_role="Agent") == []

    def test_include_names_filter(self):
        reg = self._make_registry()
        tools = capabilities_to_tools(reg, actor_role="Agent", include_names={"action_a"})
        names = [t["function"]["name"] for t in tools]
        assert names == ["action_a"]

    def test_include_names_empty_set(self):
        reg = self._make_registry()
        tools = capabilities_to_tools(reg, actor_role="Agent", include_names=set())
        assert tools == []

    def test_include_names_none_returns_all_allowed(self):
        reg = self._make_registry()
        tools = capabilities_to_tools(reg, actor_role="Agent", include_names=None)
        names = [t["function"]["name"] for t in tools]
        assert "action_a" in names
