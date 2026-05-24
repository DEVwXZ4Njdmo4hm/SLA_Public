#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         constants.py
Description:  Deployment constants including file lists and directory exclusions.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

from pathlib import Path

# Project root (one level above deploy/)
SOURCE_DIR = Path(__file__).resolve().parent.parent

SERVICE_NAME = "suricata-llm-agent"
REQUIRED_PROGRAMS = ["podman", "sudo", "systemctl"]

# Hardcoded: files required in the container build context.
COPY_FILES: list[str] = [
    "requirements.txt",
    "suspicious_ja3.toml",
    "suspicious_ja3s.toml",
]

# Hardcoded: directories required in the container build context.
COPY_DIRS: list[str] = [
    "src",
    "configs/mail_providers",
    "configs/capabilities",
]

# Directory / file names excluded when copying to the work directory.
EXCLUDE_DIR_NAMES: set[str] = {"__pycache__"}
EXCLUDE_SUFFIXES: set[str] = {".egg-info"}
