#!/usr/bin/env python3
"""Read-only federated CLI query helper for OdyAI (ChromaDB + SQLite FTS5 + DJI media timestamps)."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.local_intelligence_gateway import AuthContext
from services.docs.service import DocsService


def fmt_ts(sec: float | None) -> str:
    if sec is None:
        return "00:00"
    m, s = divmod(int(sec), 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


async def run_query(query: str, *, domain: str, scope: str, top_k: int) -> None:
    svc = DocsService()
    auth = AuthContext(
        owner="admin",
        scopes=frozenset({
            "docs:read",
            "media:read",
            "personal:read",
            "business:read",
            "tier:restricted-financial",
            "tier:restricted-pii",
        }),
        auth_method="session",
        session_id="odyai-cli",
    )

    domains = ("docs", "media") if domain == "all" else (domain,)
    owner_scopes = ("personal", "business") if scope == "all" else (scope,)

    if domain == "media":
        hits = await svc.query_local_archive(
            query,
            auth_context=auth,
            domains=domains,
            owner_scopes=owner_scopes,
            top_k=top_k,
        )
    else:
        hits = await svc.query(
            query,
            auth_context=auth,
            domains=domains,
            owner_scopes=owner_scopes,
            top_k=top_k,
        )

    print(f"\n=== ODYAI RESULTS FOR: {query!r} ({len(hits)} hits) ===\n")
    for idx, h in enumerate(hits, 1):
        meta = h.metadata or {}
        tier = meta.get("retrieval_tier", "unknown")
        hit_domain = meta.get("domain", "docs")
        name = Path(h.source).name
        loc = meta.get("location") or {}
        if hit_domain == "media" and loc:
            where = f"{fmt_ts(loc.get('start_sec'))}-{fmt_ts(loc.get('end_sec'))}"
        elif "page_number" in meta:
            where = f"p.{meta['page_number']}"
        else:
            where = meta.get("owner_scope") or "rag"
        snippet = " ".join(h.text.split())[:120]
        print(f"{idx}. [{tier} | {hit_domain} | {where}] {name} (score={h.score:.4f})")
        print(f"   Path   : {h.source}")
        print(f"   Snippet: {snippet!r}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only OdyAI federated search CLI.")
    parser.add_argument("query", help="Search query string.")
    parser.add_argument("--domain", choices=("all", "docs", "media"), default="all", help="Filter domain.")
    parser.add_argument("--scope", choices=("all", "personal", "business"), default="all", help="Filter owner scope.")
    parser.add_argument("--top-k", type=int, default=6, help="Maximum hits per retrieval tier.")
    args = parser.parse_args()
    asyncio.run(run_query(args.query, domain=args.domain, scope=args.scope, top_k=args.top_k))


if __name__ == "__main__":
    main()
