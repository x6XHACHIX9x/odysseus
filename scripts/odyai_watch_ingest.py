#!/usr/bin/env python3
r"""
OdyAI Incremental Watch-Folder & Archive Delta Orchestrator.

Safely coordinates incremental ingestion across OdyAI's isolated storage tiers
while preserving strict read-only access on G:\ and M10 Resource Governor limits:
  1. Checks evaluate_workstation_state() before doing any heavy indexing work.
  2. In --mode dry-run (default): reports current SQLite catalog, OCR queue,
     media transcription queue, and pending supervised RAG proposals without
     mutating any file or database.
  3. In --mode sync:
     - Runs read-only SHA-256 delta scan via scan_archive_catalog.py
     - Syncs & processes private/restricted OCR queue via private_ocr_indexer.py
     - Scans new media items (and optionally transcribes up to --media-limit)
       via stream_pipeline.py
     - Emits a single-use supervised approval card via odyai_maintenance.py
       (--mode propose) if new allowlisted RAG files are ready.
  4. In --mode task-status | register-task | unregister-task:
     - Manages the Windows Scheduled Task (\OdyAI\IncrementalWatchIngest)
       using pythonw.exe (no console popup) so background syncs run on a
       bounded schedule and defer immediately if OBS/games/VRAM are active.
"""

from __future__ import annotations

import argparse
import pathlib
import sqlite3
import subprocess
import sys
from typing import List, Optional

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.resource_governor import evaluate_workstation_state

CATALOG_DB = ROOT / "data" / "archive_catalog.db"
PRIVATE_OCR_DB = ROOT / "data" / "private_ocr_index.db"
STREAM_DB = ROOT / "data" / "stream_media_catalog.db"
DEFAULT_TASK_NAME = r"\OdyAI\IncrementalWatchIngest"


def _ro_connect(db_path: pathlib.Path) -> Optional[sqlite3.Connection]:
    if not db_path.exists():
        return None
    con = sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def print_status_snapshot() -> None:
    print("=== ODYAI INCREMENTAL INGESTION SNAPSHOT ===")

    cat = _ro_connect(CATALOG_DB)
    if cat:
        try:
            total = cat.execute("SELECT COUNT(*) FROM archive_files WHERE is_duplicate = 0").fetchone()[0]
            rag_ready = cat.execute(
                "SELECT COUNT(*) FROM archive_files WHERE is_duplicate = 0 AND sensitivity_tier IN ('general-rag', 'business-rag')"
            ).fetchone()[0]
            restricted = cat.execute(
                "SELECT COUNT(*) FROM archive_files WHERE is_duplicate = 0 AND sensitivity_tier IN ('restricted-financial', 'restricted-pii', 'personal-private')"
            ).fetchone()[0]
            print(f"Archive Catalog    : {total} unique files (allowlisted_rag={rag_ready}, private/restricted={restricted})")
        finally:
            cat.close()
    else:
        print("Archive Catalog    : not initialized")

    ocr = _ro_connect(PRIVATE_OCR_DB)
    if ocr:
        try:
            by_stat = dict(ocr.execute("SELECT status, COUNT(*) FROM ocr_documents GROUP BY status").fetchall())
            pages = ocr.execute("SELECT COUNT(*) FROM ocr_pages").fetchone()[0]
            print(f"Private OCR FTS5   : {by_stat} (indexed_pages={pages})")
        finally:
            ocr.close()
    else:
        print("Private OCR FTS5   : not initialized")

    media = _ro_connect(STREAM_DB)
    if media:
        try:
            by_tstat = dict(media.execute("SELECT transcript_status, COUNT(*) FROM media_items GROUP BY transcript_status").fetchall())
            segs = media.execute("SELECT COUNT(*) FROM transcript_segments_fts").fetchone()[0]
            print(f"Media Catalog      : {by_tstat} (transcript_segments={segs})")
        finally:
            media.close()
    else:
        print("Media Catalog      : not initialized")


def _resolve_background_python() -> pathlib.Path:
    py_exe = pathlib.Path(sys.executable)
    pyw = py_exe.with_name("pythonw.exe")
    return pyw if pyw.exists() else py_exe


def build_schtasks_create_cmd(
    task_name: str = DEFAULT_TASK_NAME,
    interval_hours: int = 4,
    ocr_limit: int = 10,
    media_limit: int = 0,
    watch_dir: str = "",
) -> List[str]:
    bg_py = _resolve_background_python()
    script_path = pathlib.Path(__file__).resolve()
    tr_parts = [
        f'"{bg_py}"',
        f'"{script_path}"',
        "--mode",
        "sync",
        "--ocr-limit",
        str(max(0, int(ocr_limit))),
        "--media-limit",
        str(max(0, int(media_limit))),
    ]
    if watch_dir:
        tr_parts.extend(["--watch-dir", f'"{watch_dir}"'])

    return [
        "schtasks.exe",
        "/Create",
        "/TN",
        task_name,
        "/SC",
        "HOURLY",
        "/MO",
        str(max(1, min(24, int(interval_hours)))),
        "/TR",
        " ".join(tr_parts),
        "/RL",
        "LIMITED",
        "/F",
    ]


def cmd_task_status(task_name: str = DEFAULT_TASK_NAME) -> int:
    proc = subprocess.run(
        ["schtasks.exe", "/Query", "/TN", task_name, "/FO", "LIST", "/V"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(f"Scheduled Task     : NOT REGISTERED ({task_name})")
        return 1
    print(f"=== SCHEDULED TASK STATUS ({task_name}) ===")
    keep_prefixes = (
        "TaskName:",
        "Status:",
        "Next Run Time:",
        "Last Run Time:",
        "Last Result:",
        "Task To Run:",
        "Schedule Type:",
    )
    for line in proc.stdout.splitlines():
        s = line.strip()
        if any(s.startswith(p) for p in keep_prefixes):
            print(f"  {s}")
    return 0


def cmd_register_task(
    task_name: str = DEFAULT_TASK_NAME,
    interval_hours: int = 4,
    ocr_limit: int = 10,
    media_limit: int = 0,
    watch_dir: str = "",
) -> int:
    cmd = build_schtasks_create_cmd(
        task_name=task_name,
        interval_hours=interval_hours,
        ocr_limit=ocr_limit,
        media_limit=media_limit,
        watch_dir=watch_dir,
    )
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"ERROR registering task {task_name}: {proc.stderr.strip() or proc.stdout.strip()}", file=sys.stderr)
        return proc.returncode
    print(f"[OK] Registered scheduled task {task_name} (every {interval_hours}h, M10-governed)")
    return cmd_task_status(task_name)


def cmd_unregister_task(task_name: str = DEFAULT_TASK_NAME) -> int:
    proc = subprocess.run(["schtasks.exe", "/Delete", "/TN", task_name, "/F"], capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"Scheduled task {task_name} was not registered or could not be deleted: {proc.stderr.strip()}", file=sys.stderr)
        return proc.returncode
    print(f"[OK] Removed scheduled task {task_name}")
    return 0


def _run_step(label: str, cmd: List[str]) -> int:
    print(f"\n--- {label} ---")
    proc = subprocess.run(cmd, cwd=str(ROOT))
    if proc.returncode != 0:
        print(f"[WARN] {label} exited with code {proc.returncode}", file=sys.stderr)
    return proc.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="OdyAI Incremental Watch-Folder & Delta Orchestrator")
    parser.add_argument(
        "--mode",
        choices=["dry-run", "sync", "task-status", "register-task", "unregister-task"],
        default="dry-run",
    )
    parser.add_argument("--watch-dir", type=str, default="", help="Optional extra folder root to include in read-only scan")
    parser.add_argument("--ocr-limit", type=int, default=10, help="Max private/restricted PDFs to OCR in one sync pass")
    parser.add_argument("--media-limit", type=int, default=0, help="Max pending media files to transcribe in one sync pass (0 = scan only)")
    parser.add_argument("--task-name", type=str, default=DEFAULT_TASK_NAME, help="Windows Scheduled Task path")
    parser.add_argument("--interval-hours", type=int, default=4, help="Hourly interval for --mode register-task (1-24)")
    parser.add_argument("--force", action="store_true", help="Proceed even if workstation is currently busy")
    args = parser.parse_args()

    if args.mode == "task-status":
        return cmd_task_status(task_name=args.task_name)
    if args.mode == "register-task":
        return cmd_register_task(
            task_name=args.task_name,
            interval_hours=args.interval_hours,
            ocr_limit=args.ocr_limit,
            media_limit=args.media_limit,
            watch_dir=args.watch_dir,
        )
    if args.mode == "unregister-task":
        return cmd_unregister_task(task_name=args.task_name)

    gov = evaluate_workstation_state()
    allowed = bool(gov.get("allowed", False))
    verdict = str(gov.get("verdict", "DEFERRED"))
    blockers = gov.get("blockers") or []
    print(f"M10 Resource Gate  : verdict={verdict} allowed={allowed} (blockers={blockers or 'none'})")

    print_status_snapshot()

    if args.mode == "dry-run":
        print("\n[DRY-RUN] No files or databases were modified. Run with --mode sync to execute incremental update.")
        return 0

    if not allowed and not args.force:
        print(f"[DEFERRED] Workstation busy ({', '.join(blockers)}); deferring sync. Use --force to override.", file=sys.stderr)
        return 75

    py = sys.executable

    scan_cmd = [py, "scripts/scan_archive_catalog.py"]
    if args.watch_dir:
        watch_path = pathlib.Path(args.watch_dir)
        if not watch_path.exists():
            print(f"ERROR: --watch-dir does not exist: {watch_path}", file=sys.stderr)
            return 2
        scan_cmd.extend(
            [
                "--roots",
                "G:/01_WE_ALL_SHINE_LLC",
                "G:/02_PERSONAL_ARCHIVE",
                "G:/03_CONTENT_AND_MEDIA",
                "G:/Ody_AI Organized",
                "G:/Ody_AI Workspace",
                str(watch_path),
            ]
        )
    rc = _run_step("1/4 Read-Only Archive Catalog Delta Scan", scan_cmd)
    if rc != 0:
        return rc

    rc = _run_step("2/4 Sync & Process Private/Restricted OCR Queue", [py, "scripts/private_ocr_indexer.py", "--mode", "sync-queue"])
    if rc == 0 and args.ocr_limit > 0:
        _run_step(f"2b/4 Run RapidOCR Batch (limit={args.ocr_limit})", [py, "scripts/private_ocr_indexer.py", "--mode", "run", "--limit", str(args.ocr_limit), *(["--force"] if args.force else [])])

    rc = _run_step("3/4 Scan Media & Stream Roots", [py, "scripts/stream_pipeline.py", "--mode", "scan"])
    if rc == 0 and args.media_limit > 0:
        _run_step(f"3b/4 Transcribe Pending Media (limit={args.media_limit})", [py, "scripts/stream_pipeline.py", "--mode", "transcribe", "--limit", str(args.media_limit)])

    _run_step("4/4 Generate Supervised RAG Proposal (if allowlisted delta exists)", [py, "scripts/odyai_maintenance.py", "--mode", "propose"])

    print("\n=== POST-SYNC SNAPSHOT ===")
    print_status_snapshot()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
