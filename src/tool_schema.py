#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         tool_schema.py
Description:  Capability to Ollama tool schema translator for JSON Schema generation.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .executor.models import Capability, ParamConstraint
from .executor.registry import CapabilityRegistry

logger = logging.getLogger(__name__)

# Mapping from capability param types to JSON Schema types
_TYPE_MAP: Dict[str, str] = {
    "string": "string",
    "integer": "integer",
    "float": "number",
    "boolean": "boolean",
}


def capability_to_tool(cap: Capability) -> Dict[str, Any]:
    """Convert a single :class:`Capability` to an Ollama tool definition.

    Returns a dict of the form::

        {
            "type": "function",
            "function": {
                "name": "...",
                "description": "...",
                "parameters": {
                    "type": "object",
                    "properties": { ... },
                    "required": [ ... ],
                },
            },
        }
    """
    properties: Dict[str, Any] = {}
    required: List[str] = []

    for param in cap.params:
        prop = _param_to_json_schema(param)
        properties[param.name] = prop
        if param.required:
            required.append(param.name)

    parameters: Dict[str, Any] = {
        "type": "object",
        "properties": properties,
    }
    if required:
        parameters["required"] = required

    return {
        "type": "function",
        "function": {
            "name": cap.name,
            "description": cap.description or f"Execute the '{cap.name}' action.",
            "parameters": parameters,
        },
    }


def capabilities_to_tools(
    registry: CapabilityRegistry,
    actor_role: str = "Agent",
    include_names: Optional[set] = None,
) -> List[Dict[str, Any]]:
    """Convert all enabled capabilities accessible to *actor_role* into
    a list of Ollama tool definitions.

    Only capabilities that are enabled **and** include *actor_role* in
    their ``allowed_roles`` are included.

    Parameters
    ----------
    include_names:
        If provided, only capabilities whose name is in this set are
        included.  Use this to scope available tools per context
        (e.g. realtime analysis vs. daily report).
    """
    tools: List[Dict[str, Any]] = []
    for name in registry.list_names():
        if include_names is not None and name not in include_names:
            continue
        cap = registry.get(name)
        if cap is None or not cap.enabled:
            continue
        if cap.allowed_roles and actor_role not in cap.allowed_roles:
            continue
        tools.append(capability_to_tool(cap))
    return tools


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _param_to_json_schema(param: ParamConstraint) -> Dict[str, Any]:
    """Convert a :class:`ParamConstraint` to a JSON Schema property."""
    schema: Dict[str, Any] = {
        "type": _TYPE_MAP.get(param.type, "string"),
    }
    if param.name:
        schema["description"] = param.name
    if param.choices:
        schema["enum"] = param.choices
    # Note: ``pattern`` is intentionally omitted — regex constraints
    # are enforced by the PolicyEngine at execution time, not by the
    # LLM schema.
    return schema
