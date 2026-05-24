#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         test_deploy_workdir.py
Description:  Tests for deploy.workdir local override resolution.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

from types import SimpleNamespace

import deploy.workdir as workdir


def test_prepare_work_dir_prefers_group_local_runtime_files(tmp_path, monkeypatch):
    source_root = tmp_path / "source"
    group_root = tmp_path / "group"
    work_root = tmp_path / "work"

    source_root.mkdir()
    group_root.mkdir()

    (source_root / "requirements.txt").write_text("root requirements\n", encoding="utf-8")
    (source_root / "llm_prompt.toml").write_text('root = "prompt"\n', encoding="utf-8")
    (source_root / "ModelProfiles.toml").write_text('root = "model"\n', encoding="utf-8")

    (source_root / "src").mkdir()
    (source_root / "src" / "__init__.py").write_text("", encoding="utf-8")
    (source_root / "configs" / "mail_providers").mkdir(parents=True)
    (source_root / "configs" / "mail_providers" / "outlook.toml").write_text("[mail_provider]\n", encoding="utf-8")
    (source_root / "configs" / "capabilities").mkdir(parents=True)
    (source_root / "configs" / "capabilities" / "dummy.toml").write_text("name = 'dummy'\n", encoding="utf-8")

    (group_root / "suricata-llm-agent.toml").write_text("[llm]\nprompt_file='llm_prompt.toml'\n", encoding="utf-8")
    (group_root / "llm_prompt.toml").write_text('group = "prompt"\n', encoding="utf-8")
    (group_root / "ModelProfiles.toml").write_text('group = "model"\n', encoding="utf-8")

    monkeypatch.setattr(workdir, "SOURCE_DIR", source_root)
    monkeypatch.setattr(workdir, "COPY_FILES", ["requirements.txt"])
    monkeypatch.setattr(workdir, "COPY_DIRS", ["src", "configs/mail_providers", "configs/capabilities"])

    cfg = SimpleNamespace(
        work_dir=work_root,
        deploy={"container": {"extra_files": []}},
        agent_conf_path=group_root / "suricata-llm-agent.toml",
        _base_dir=group_root,
    )

    output = workdir._prepare_work_dir(
        cfg,
        implicit_files=["llm_prompt.toml", "ModelProfiles.toml"],
        implicit_dirs=[],
    )

    assert (output / "llm_prompt.toml").read_text(encoding="utf-8") == 'group = "prompt"\n'
    assert (output / "ModelProfiles.toml").read_text(encoding="utf-8") == 'group = "model"\n'
