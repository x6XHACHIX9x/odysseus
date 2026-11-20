"""Unit tests for OdyAI incremental watch-folder orchestrator & Task Scheduler helper."""

from __future__ import annotations

import sys

import scripts.odyai_watch_ingest as wi


def test_build_schtasks_create_cmd_uses_hidden_pythonw_and_m10_sync() -> None:
    cmd = wi.build_schtasks_create_cmd(
        task_name=r"\OdyAI\IncrementalWatchIngest",
        interval_hours=6,
        ocr_limit=8,
        media_limit=1,
        watch_dir=r"G:\Ody_AI Organized\99 - Review Queue",
    )
    assert cmd[:4] == ["schtasks.exe", "/Create", "/TN", r"\OdyAI\IncrementalWatchIngest"]
    assert "/RL" in cmd and cmd[cmd.index("/RL") + 1] == "LIMITED"
    assert cmd[cmd.index("/MO") + 1] == "6"
    tr = cmd[cmd.index("/TR") + 1]
    assert "--mode sync" in tr
    assert "--ocr-limit 8" in tr
    assert "--media-limit 1" in tr
    assert "99 - Review Queue" in tr


def test_sync_defers_with_exit_75_when_workstation_busy(monkeypatch) -> None:
    monkeypatch.setattr(
        wi,
        "evaluate_workstation_state",
        lambda: {"allowed": False, "verdict": "DEFERRED", "blockers": ["active_streaming:obs64.exe"]},
    )
    monkeypatch.setattr(wi, "print_status_snapshot", lambda: None)
    monkeypatch.setattr(sys, "argv", ["odyai_watch_ingest.py", "--mode", "sync"])
    assert wi.main() == 75
