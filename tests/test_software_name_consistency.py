#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_software_name_consistency.py
Description:  Software identity and source header consistency checks.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from pathlib import Path
import subprocess

from src.versioning import SOFTWARE_NAME, SOFTWARE_NAME_SUFFIX


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OLD_NAME = "Suricata " + "Log LLM Analyzer"
CANONICAL_NAME = "Suricata LLM Agent"
SOURCE_DIRS = ("src", "deploy", "tests")
HEADER_LINE_COUNT = 10


def _tracked_files() -> list[Path]:
    output = subprocess.check_output(
        ["git", "ls-files"],
        cwd=PROJECT_ROOT,
        text=True,
    )
    return [PROJECT_ROOT / line for line in output.splitlines() if line]


def _is_source_scope(path: Path) -> bool:
    relative_path = path.relative_to(PROJECT_ROOT)
    return relative_path.parts[:1] in ((name,) for name in SOURCE_DIRS)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _target_python_files() -> list[Path]:
    return sorted(
        path
        for source_dir in SOURCE_DIRS
        for path in (PROJECT_ROOT / source_dir).rglob("*.py")
        if "__pycache__" not in path.parts
    )


def test_legacy_software_name_is_absent_from_source_scope() -> None:
    offenders = [
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in _target_python_files()
        if OLD_NAME in _read_text(path)
    ]

    assert offenders == []


def test_root_python_files_are_outside_header_scope() -> None:
    root_python_files = {
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in PROJECT_ROOT.glob("*.py")
        if path.is_file()
    }
    scanned_files = {
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in _target_python_files()
    }

    assert root_python_files.isdisjoint(scanned_files)


def test_tracked_source_files_are_in_header_scope() -> None:
    scanned_files = set(_target_python_files())
    unscanned = [
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in _tracked_files()
        if path.suffix == ".py"
        and _is_source_scope(path)
        and path not in scanned_files
    ]

    assert unscanned == []


def test_software_name_constant_uses_canonical_agent_name() -> None:
    assert SOFTWARE_NAME == CANONICAL_NAME
    assert SOFTWARE_NAME_SUFFIX == "(Milestone 1)"


def test_source_file_headers_keep_milestone_format_with_canonical_name() -> None:
    offenders = []
    for path in _target_python_files():
        relative_path = path.relative_to(PROJECT_ROOT)
        header = "\n".join(_read_text(path).splitlines()[:6])
        if "Milestone" in header and f"{CANONICAL_NAME} (Milestone 1)" not in header:
            offenders.append(relative_path.as_posix())

    assert offenders == []


def test_source_file_headers_use_canonical_template_without_dates() -> None:
    offenders = []

    for path in _target_python_files():
        relative_path = path.relative_to(PROJECT_ROOT).as_posix()
        lines = _read_text(path).splitlines()
        header = lines[:HEADER_LINE_COUNT]

        if len(header) < HEADER_LINE_COUNT:
            offenders.append(f"{relative_path}: header too short")
            continue

        expected_prefix = [
            "#!/usr/bin/env python3",
            '"""',
            f"{CANONICAL_NAME} (Milestone 1)",
            "A tool to analyze Suricata logs using a large language model (LLM).",
            "",
            f"File:         {path.name}",
        ]
        expected_suffix = [
            "Author:       Capri XXI (qxwzj@hotmail.com)",
            "License:      MIT",
            '"""',
        ]

        if header[:6] != expected_prefix:
            offenders.append(f"{relative_path}: header prefix")
        if not header[6].startswith("Description:  ") or len(header[6].strip()) <= len("Description:"):
            offenders.append(f"{relative_path}: description")
        if header[7:10] != expected_suffix:
            offenders.append(f"{relative_path}: author/license/closing quote")
        if any(line.startswith("Date:") for line in header):
            offenders.append(f"{relative_path}: date")

    assert offenders == []
