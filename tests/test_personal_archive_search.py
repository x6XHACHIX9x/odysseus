"""Tests for POST /api/personal/archive/search fail-closed scope & PII gating."""

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes.personal_routes import setup_personal_routes
from services.docs.service import DocChunk, DocsService


class _DummyPersonalMgr:
    index: List[Dict[str, Any]] = []

    def get_indexed_directories(self) -> List[str]:
        return []

    def add_directory(self, *args: Any, **kwargs: Any) -> None:
        pass

    def exclude_file(self, *args: Any, **kwargs: Any) -> None:
        pass


class _StubAuthManager:
    is_configured = True

    def __init__(self, admins: Iterable[str] = ("hachi",), denied_docs: Iterable[str] = ()) -> None:
        self._admins = set(admins)
        self._denied_docs = set(denied_docs)

    def is_admin(self, user: str) -> bool:
        return user in self._admins

    def get_privileges(self, user: str) -> Dict[str, Any]:
        if user in self._admins:
            return {"can_use_documents": True}
        return {"can_use_documents": user not in self._denied_docs}


def _build_test_client(auth_mgr: _StubAuthManager) -> TestClient:
    app = FastAPI()
    app.state.auth_manager = auth_mgr

    @app.middleware("http")
    async def _inject_user(request, call_next):
        hdr_user = request.headers.get("x-test-user")
        if hdr_user:
            request.state.current_user = hdr_user
        if request.headers.get("x-api-token") == "1":
            request.state.api_token = True
        return await call_next(request)

    app.include_router(setup_personal_routes(_DummyPersonalMgr(), None, False))
    return TestClient(app)


def test_archive_search_rejects_unauthenticated() -> None:
    client = _build_test_client(_StubAuthManager())
    res = client.post("/api/personal/archive/search", json={"query": "Wells Fargo"})
    assert res.status_code == 401


def test_archive_search_rejects_api_token() -> None:
    client = _build_test_client(_StubAuthManager())
    res = client.post(
        "/api/personal/archive/search",
        headers={"x-test-user": "api", "x-api-token": "1"},
        json={"query": "Wells Fargo"},
    )
    assert res.status_code == 403


def test_archive_search_rejects_non_admin_without_document_privilege() -> None:
    client = _build_test_client(_StubAuthManager(denied_docs=("restricted_user",)))
    res = client.post(
        "/api/personal/archive/search",
        headers={"x-test-user": "restricted_user"},
        json={"query": "notes", "owner_scopes": ["personal"]},
    )
    assert res.status_code == 403


def test_archive_search_rejects_non_admin_requesting_business_scope() -> None:
    client = _build_test_client(_StubAuthManager())
    res = client.post(
        "/api/personal/archive/search",
        headers={"x-test-user": "standard_user"},
        json={"query": "We All Shine", "owner_scopes": ["business"], "gateway_only": True},
    )
    assert res.status_code == 403
    assert "business:read" in res.json()["detail"]


def test_archive_search_allows_non_admin_personal_scope_only(monkeypatch) -> None:
    captured: Dict[str, Any] = {}

    async def _fake_query_local_archive(
        self,
        query: str,
        *,
        auth_context: Any,
        domains: Iterable[str] = ("docs", "media"),
        owner_scopes: Iterable[str] = ("personal", "business"),
        max_sensitivity: Optional[str] = None,
        top_k: int = 5,
        suppress_restricted_pii: bool = True,
        redact_sensitive: bool = True,
        **kwargs: Any,
    ) -> List[DocChunk]:
        captured["scopes"] = set(auth_context.scopes)
        captured["owner_scopes"] = tuple(owner_scopes)
        return [
            DocChunk(
                text="Personal studio setup note",
                source="G:/Ody_AI Organized/Personal/studio.md",
                score=0.91,
                metadata={
                    "retrieval_tier": "local_intelligence_gateway",
                    "domain": "docs",
                    "owner_scope": "personal",
                    "filename": "studio.md",
                    "location": {"page": 1},
                    "redacted": False,
                },
            )
        ]

    monkeypatch.setattr(DocsService, "query_local_archive", _fake_query_local_archive)
    client = _build_test_client(_StubAuthManager())
    res = client.post(
        "/api/personal/archive/search",
        headers={"x-test-user": "standard_user"},
        json={"query": "studio", "owner_scopes": ["personal"], "gateway_only": True},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["count"] == 1
    assert body["results"][0]["owner_scope"] == "personal"
    assert "business:read" not in captured["scopes"]
    assert "tier:restricted-financial" not in captured["scopes"]
    assert captured["owner_scopes"] == ("personal",)


def test_archive_search_grants_admin_full_scopes_and_returns_redacted_hits(monkeypatch) -> None:
    captured: Dict[str, Any] = {}

    async def _fake_query(
        self,
        query: str,
        top_k: int = 5,
        *,
        auth_context: Any = None,
        domains: Iterable[str] = ("docs", "media"),
        owner_scopes: Iterable[str] = ("personal", "business"),
        **kwargs: Any,
    ) -> List[DocChunk]:
        captured["scopes"] = set(auth_context.scopes)
        return [
            DocChunk(
                text="Wells Fargo Business Checking [REDACTED-ACCOUNT] We All Shine, LLC",
                source="G:/Ody_AI Organized/Business/We All Shine,LLC/08-31-26 Stmt.pdf",
                score=0.985,
                metadata={
                    "retrieval_tier": "local_intelligence_gateway",
                    "domain": "docs",
                    "owner_scope": "business",
                    "category": "banking",
                    "filename": "08-31-26 Stmt.pdf",
                    "location": {"page": 1},
                    "redacted": True,
                },
            )
        ]

    monkeypatch.setattr(DocsService, "query", _fake_query)
    client = _build_test_client(_StubAuthManager())
    res = client.post(
        "/api/personal/archive/search",
        headers={"x-test-user": "hachi"},
        json={"query": "We All Shine Wells Fargo", "owner_scopes": ["personal", "business"], "gateway_only": False},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["count"] == 1
    assert body["results"][0]["filename"] == "08-31-26 Stmt.pdf"
    assert body["results"][0]["redacted"] is True
    assert {"docs:read", "media:read", "personal:read", "business:read", "tier:restricted-financial", "tier:restricted-pii"} <= captured["scopes"]


def test_media_draft_endpoint_requires_auth_and_generates_human_approved_draft(tmp_path, monkeypatch) -> None:
    import json
    import sqlite3
    import scripts.stream_pipeline as sp

    fake_db = tmp_path / "stream_media_catalog.db"
    fake_drafts = tmp_path / "stream_drafts"
    con = sqlite3.connect(str(fake_db))
    con.executescript(
        """
        CREATE TABLE media_items (
            id INTEGER PRIMARY KEY,
            source_path TEXT,
            filename TEXT,
            ext TEXT,
            size_bytes INTEGER,
            is_duplicate INTEGER DEFAULT 0,
            media_role TEXT,
            paired_audio_path TEXT,
            duration_sec REAL,
            resolution TEXT,
            transcript_json_path TEXT
        );
        CREATE TABLE publishing_drafts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            draft_id TEXT,
            media_id INTEGER,
            created_at TEXT,
            status TEXT,
            draft_md_path TEXT,
            draft_json_path TEXT
        );
        INSERT INTO media_items (id, source_path, filename, ext, size_bytes, is_duplicate, media_role)
        VALUES (7, 'G:/03_CONTENT_AND_MEDIA/clip_07.mp4', 'clip_07.mp4', '.mp4', 10485760, 0, 'dji_camera_clip');
        """
    )
    con.commit()
    con.close()

    monkeypatch.setattr(sp, "STREAM_DB", fake_db)
    monkeypatch.setattr(sp, "DRAFT_DIR", fake_drafts)
    monkeypatch.setattr(sp, "probe_video_meta", lambda path, ext: (42.5, "1920x1080"))

    client = _build_test_client(_StubAuthManager())

    r_unauth = client.post("/api/personal/archive/media-draft", json={"media_id": 7})
    assert r_unauth.status_code == 401

    r_ok = client.post(
        "/api/personal/archive/media-draft",
        headers={"x-test-user": "hachi"},
        json={
            "media_id": 7,
            "highlight_start_ts": "00:01:12",
            "highlight_end_ts": "00:01:28",
            "highlight_quote": "Testing the new studio mic chain",
        },
    )
    assert r_ok.status_code == 200, r_ok.text
    body = r_ok.json()
    assert body["success"] is True
    assert body["status"] == "awaiting_human_approval"
    assert body["auto_upload_blocked"] is True

    j_data = json.loads(Path(body["draft_json_path"]).read_text(encoding="utf-8"))
    assert j_data["matched_highlight"]["start_ts"] == "00:01:12"
    assert j_data["auto_upload_blocked"] is True
