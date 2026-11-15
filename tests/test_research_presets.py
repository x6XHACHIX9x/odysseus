"""Unit tests for Deep Research local hardware presets (small, medium, large)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from src.research_presets import (
    ALLOWED_HARDWARE_PRESETS,
    get_research_preset,
    list_research_presets,
    normalize_hardware_preset,
)
from src.research_handler import ResearchHandler
from routes.research.research_routes import setup_research_routes


def _build_test_client():
    app = FastAPI()
    handler = MagicMock()
    handler.start_research = MagicMock(return_value={"session_id": "test-sid", "status": "running"})
    with (
        patch("routes.research.research_routes.get_current_user", return_value="admin"),
        patch("src.auth_helpers.require_privilege", return_value="admin"),
    ):
        app.include_router(setup_research_routes(handler))
    return TestClient(app), handler


def test_presets_cover_small_medium_large_with_monotonic_budgets():
    presets = list_research_presets()
    assert [p["id"] for p in presets] == list(ALLOWED_HARDWARE_PRESETS)

    small = get_research_preset("small")
    medium = get_research_preset("medium")
    large = get_research_preset("large")

    assert small["max_rounds"] < medium["max_rounds"] < large["max_rounds"]
    assert small["max_content_chars"] < medium["max_content_chars"] < large["max_content_chars"]
    assert small["max_report_tokens"] < medium["max_report_tokens"] < large["max_report_tokens"]
    assert small["extraction_concurrency"] < medium["extraction_concurrency"] < large["extraction_concurrency"]
    assert small["synthesis_window"] < medium["synthesis_window"] < large["synthesis_window"]


def test_normalize_hardware_preset_handles_auto_and_invalid():
    assert normalize_hardware_preset(None) is None
    assert normalize_hardware_preset("") is None
    assert normalize_hardware_preset("AUTO") is None
    assert normalize_hardware_preset(" Medium ") == "medium"
    with pytest.raises(ValueError, match="Unsupported hardware preset"):
        normalize_hardware_preset("giant")


def test_research_routes_expose_presets_and_forward_hardware_preset():
    app = FastAPI()
    handler = MagicMock()
    handler.start_research = MagicMock(return_value={"session_id": "test-sid", "status": "running"})
    app.include_router(setup_research_routes(handler))
    client = TestClient(app)

    with (
        patch("routes.research.research_routes.get_current_user", return_value="admin"),
        patch("src.auth_helpers.require_privilege", return_value="admin"),
        patch("routes.research.research_routes.resolve_endpoint", return_value=("http://127.0.0.1:11434/v1/chat/completions", "qwen3:8b", {})),
    ):
        res_list = client.get("/api/research/presets")
        assert res_list.status_code == 200
        ids = [p["id"] for p in res_list.json()["presets"]]
        assert ids == ["small", "medium", "large"]

        res_start = client.post(
            "/api/research/start",
            json={"query": "Compare local inference engines", "hardware_preset": "small"},
        )
        assert res_start.status_code == 200
        kwargs = handler.start_research.call_args.kwargs
        assert kwargs["hardware_preset"] == "small"
        assert kwargs["max_rounds"] == 4
        assert kwargs["max_time"] == 240

        res_bad = client.post(
            "/api/research/start",
            json={"query": "Compare local inference engines", "hardware_preset": "giant"},
        )
        assert res_bad.status_code == 422


def test_call_research_service_applies_small_preset_and_respects_overrides():
    handler = ResearchHandler()
    captured_kwargs = {}

    class DummyResearcher:
        def __init__(self, **kwargs):
            captured_kwargs.update(kwargs)
            self.findings = []
            self.analyzed_urls = []
            self.round_count = 1
            self.providers_used = []
            self.evolving_report = ""

        async def research(self, *args, **kwargs):
            return "Final report"

        def get_stats(self):
            return {"rounds": 1, "sources": 0}

    with (
        patch.object(handler, "_probe_endpoint", new=AsyncMock()),
        patch("src.deep_research.DeepResearcher", side_effect=DummyResearcher),
    ):
        asyncio.run(
            handler.call_research_service(
                query="Test small preset",
                llm_endpoint="http://127.0.0.1:11434/v1/chat/completions",
                llm_model="qwen3:8b",
                max_rounds=0,
                extraction_concurrency=2,
                hardware_preset="small",
            )
        )

    assert captured_kwargs["max_rounds"] == 4
    assert captured_kwargs["max_urls_per_round"] == 2
    assert captured_kwargs["max_content_chars"] == 8000
    assert captured_kwargs["max_report_tokens"] == 4096
    assert captured_kwargs["synthesis_window"] == 6
    # Explicit override wins over small preset default (1)
    assert captured_kwargs["extraction_concurrency"] == 2
