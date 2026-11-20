import sqlite3
from pathlib import Path
from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import personal_routes


def _build_test_app(monkeypatch, tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    archive_db = data_dir / "archive_catalog.db"
    acon = sqlite3.connect(str(archive_db))
    acon.execute(
        """
        CREATE TABLE archive_files (
            id INTEGER PRIMARY KEY,
            sha256 TEXT,
            size_bytes INTEGER,
            ext TEXT,
            current_path TEXT,
            current_top_folder TEXT,
            proposed_category TEXT,
            owner_scope TEXT,
            sensitivity_tier TEXT,
            confidence REAL,
            is_duplicate INTEGER DEFAULT 0,
            duplicate_of TEXT,
            needs_ocr INTEGER DEFAULT 0,
            snippet_preview TEXT
        )
        """
    )
    acon.execute(
        """
        INSERT INTO archive_files (id, sha256, size_bytes, ext, current_path, current_top_folder,
            proposed_category, owner_scope, sensitivity_tier, confidence, is_duplicate, needs_ocr, snippet_preview)
        VALUES (101, 'abc123sha', 2048, '.pdf', 'G:/Business/WeAllShine_Invoice.pdf', 'Business',
            'uncategorized', 'personal', 'personal-private', 0.55, 0, 1, '')
        """
    )
    acon.commit()
    acon.close()

    inv_db = data_dir / "drive_inventory.db"
    icon = sqlite3.connect(str(inv_db))
    icon.execute(
        """
        CREATE TABLE inventory_files (
            id INTEGER PRIMARY KEY,
            sha256 TEXT,
            catalog_category TEXT,
            proposed_category TEXT,
            catalog_owner_scope TEXT,
            proposed_owner_scope TEXT,
            sensitivity_tier TEXT,
            snippet_preview TEXT,
            confidence REAL
        )
        """
    )
    icon.execute(
        """
        INSERT INTO inventory_files (id, sha256, catalog_category, proposed_category,
            catalog_owner_scope, proposed_owner_scope, sensitivity_tier, snippet_preview, confidence)
        VALUES (1, 'abc123sha', 'uncategorized', 'uncategorized', 'personal', 'personal', 'personal-private', '', 0.55)
        """
    )
    icon.commit()
    icon.close()

    ocr_db = data_dir / "private_ocr_index.db"
    ocon = sqlite3.connect(str(ocr_db))
    ocon.execute("CREATE TABLE ocr_pages (id INTEGER PRIMARY KEY, sha256 TEXT, page_num INTEGER, extracted_text TEXT, mean_confidence REAL)")
    ocon.execute("INSERT INTO ocr_pages (sha256, page_num, extracted_text, mean_confidence) VALUES ('abc123sha', 1, 'We All Shine LLC DTF Transfer Invoice #4021', 0.96)")
    ocon.commit()
    ocon.close()

    # Point personal_routes.__file__ resolution at tmp_path/routes/personal_routes.py
    fake_routes_dir = tmp_path / "routes"
    fake_routes_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(personal_routes, "__file__", str(fake_routes_dir / "personal_routes.py"))
    monkeypatch.setattr(personal_routes, "auth_disabled", lambda: True)

    class DummyMgr:
        index = []

    app = FastAPI()
    app.dependency_overrides[personal_routes.require_user] = lambda: "admin"
    app.include_router(personal_routes.setup_personal_routes(DummyMgr(), None, False))
    return TestClient(app), archive_db, inv_db


def test_list_and_confirm_archive_metadata(monkeypatch, tmp_path):
    client, archive_db, inv_db = _build_test_app(monkeypatch, tmp_path)

    res = client.get("/api/personal/archive/metadata?review_status=unconfirmed")
    assert res.status_code == 200
    body = res.json()
    assert body["unconfirmed_count"] == 1
    assert body["confirmed_count"] == 0
    rec = body["records"][0]
    assert rec["id"] == 101
    assert "We All Shine LLC DTF Transfer Invoice #4021" in rec["extracted_content"]

    upd = client.post(
        "/api/personal/archive/metadata/update",
        json={
            "record_id": 101,
            "proposed_category": "invoices_dtf",
            "owner_scope": "business",
            "sensitivity_tier": "business-rag",
            "snippet_preview": "We All Shine LLC DTF Invoice #4021",
            "confirmed": True,
        },
    )
    assert upd.status_code == 200
    ubody = upd.json()
    assert ubody["metadata_confirmed"] is True
    assert ubody["inventory_rows_synced"] == 1

    # Verify both SQLite databases persisted the confirmed metadata
    acon = sqlite3.connect(str(archive_db))
    arow = acon.execute("SELECT proposed_category, owner_scope, sensitivity_tier, confidence, metadata_confirmed FROM archive_files WHERE id = 101").fetchone()
    acon.close()
    assert arow == ("invoices_dtf", "business", "business-rag", 1.0, 1)

    icon = sqlite3.connect(str(inv_db))
    irow = icon.execute("SELECT catalog_category, proposed_owner_scope, sensitivity_tier, confidence FROM inventory_files WHERE sha256 = 'abc123sha'").fetchone()
    icon.close()
    assert irow == ("invoices_dtf", "business", "business-rag", 1.0)
