#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         log.py
Description:  ANSI color logging helpers and status message printers.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import sys

_IS_TTY = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _IS_TTY else text


def _info(msg: str) -> None:
    print(_c("1;34", "[INFO] ") + msg)


def _ok(msg: str) -> None:
    print(_c("1;32", "[OK]   ") + msg)


def _warn(msg: str) -> None:
    print(_c("1;33", "[WARN] ") + msg, file=sys.stderr)


def _err(msg: str) -> None:
    print(_c("1;31", "[ERR]  ") + msg, file=sys.stderr)


def _fatal(msg: str) -> None:
    _err(msg)
    sys.exit(1)
