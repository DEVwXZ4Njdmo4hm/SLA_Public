#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         template.py
Description:  Template engine with variable substitution and block injection.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .log import _fatal
from .utils import _resolve_dotpath

_VAR_RE = re.compile(r"(?<!@)@([a-zA-Z][a-zA-Z0-9_.]*[a-zA-Z0-9])@(?!@)")
_BLOCK_RE = re.compile(r"^\s*@@\s*(.+?)\s*@@\s*$")


def _render_template(
    template_path: Path,
    variables: dict[str, str],
    blocks: dict[str, str],
    ref_sources: dict[str, dict[str, Any]] | None = None,
) -> str:
    """
    Render a template file with variable and block substitution.

    Block substitution:  Lines matching ``@@ NAME @@`` are replaced by the
    corresponding entry in *blocks*.  An empty string removes the line.

    Variable substitution:  ``@name@`` tokens are resolved from *variables*.
    Dot-prefixed names like ``@secrets.x.y@`` are resolved via *ref_sources*:
    the first segment selects the source dict, the remainder is a dotpath.
    """
    if ref_sources is None:
        ref_sources = {}

    text = template_path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    output: list[str] = []

    for line in lines:
        stripped = line.rstrip("\n\r")
        block_m = _BLOCK_RE.match(stripped)
        if block_m:
            block_name = block_m.group(1)
            content = blocks.get(block_name)
            if content is None:
                _fatal(
                    f"模板 '{template_path.name}' 中引用了未定义的块: "
                    f"'@@ {block_name} @@'"
                )
            if content:  # non-empty → inject with trailing newline
                if not content.endswith("\n"):
                    content += "\n"
                output.append(content)
            # empty block → line removed entirely
            continue
        output.append(line)

    rendered = "".join(output)

    def _resolve_var(m: re.Match) -> str:
        name = m.group(1)
        # Reference sources (e.g. extra.some.nested.value)
        if "." in name:
            prefix, rest = name.split(".", 1)
            if prefix in ref_sources:
                return _resolve_dotpath(ref_sources[prefix], rest)
        if name in variables:
            return variables[name]
        _fatal(
            f"模板 '{template_path.name}' 中引用了未定义的变量: '@{name}@'"
        )
        return ""  # unreachable

    rendered = _VAR_RE.sub(_resolve_var, rendered)
    return rendered
