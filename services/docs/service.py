# services/docs/service.py
"""Docs service — unified document RAG and controlled local archive search."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from src.constants import CHROMA_DIR
from src.rag_manager import RAGManager

try:
    from scripts.local_intelligence_gateway import (
        AuthContext,
        DEFAULT_INVENTORY_DB,
        DEFAULT_MEDIA_DB,
        DEFAULT_OCR_DB,
        search_local_intelligence,
    )
except ImportError:  # pragma: no cover - fallback when scripts is not on sys.path
    AuthContext = Any  # type: ignore[misc,assignment]
    DEFAULT_OCR_DB = Path("data/private_ocr_index.db")
    DEFAULT_MEDIA_DB = Path("data/stream_media_catalog.db")
    DEFAULT_INVENTORY_DB = Path("data/drive_inventory.db")
    search_local_intelligence = None  # type: ignore[assignment]


@dataclass
class DocChunk:
    """A retrieved document or transcript chunk."""
    text: str
    source: str
    score: float
    metadata: Dict[str, Any] = None


@dataclass
class IndexResult:
    """Result of indexing documents."""
    indexed: int
    failed: int
    errors: List[str]


class DocsService:
    """
    Document RAG and controlled local intelligence service.

    - General/business RAG queries route to ChromaDB via RAGManager.
    - Authenticated archive/OCR/media queries route through
      local_intelligence_gateway (strict read-only SQLite FTS5 + policy gate).
    """

    def __init__(self, persist_dir: str = CHROMA_DIR):
        self.rag = RAGManager(persist_directory=persist_dir)

    async def query(
        self,
        query: str,
        top_k: int = 5,
        *,
        auth_context: Optional[AuthContext] = None,
        domains: Iterable[str] = ("docs", "media"),
        owner_scopes: Iterable[str] = ("personal", "business"),
        max_sensitivity: str = "restricted-pii",
        suppress_restricted_pii: bool = True,
    ) -> List[DocChunk]:
        """
        Query the document index, optionally federating authorized local
        archive/OCR/media hits when an authenticated AuthContext is provided.
        """
        results = self.rag.search(query, k=top_k)
        chunks: List[DocChunk] = []

        for result in results:
            if not isinstance(result, dict):
                continue

            metadata = result.get("metadata")
            if not isinstance(metadata, dict):
                metadata = {}
            metadata.setdefault("retrieval_tier", "chroma_rag")

            text = (
                result.get("document")
                if result.get("document") is not None
                else result.get("text")
                if result.get("text") is not None
                else result.get("content")
                if result.get("content") is not None
                else ""
            )

            source = result.get("source") or metadata.get("source") or "unknown"
            score = (
                result.get("similarity")
                if result.get("similarity") is not None
                else result.get("score")
                if result.get("score") is not None
                else 0.0
            )

            chunks.append(
                DocChunk(
                    text=text,
                    source=source,
                    score=float(score),
                    metadata=metadata,
                )
            )

        if auth_context is not None:
            archive_chunks = await self.query_local_archive(
                query,
                auth_context=auth_context,
                domains=domains,
                owner_scopes=owner_scopes,
                max_sensitivity=max_sensitivity,
                top_k=top_k,
                suppress_restricted_pii=suppress_restricted_pii,
            )
            chunks.extend(archive_chunks)

        return chunks

    async def query_local_archive(
        self,
        query: str,
        *,
        auth_context: AuthContext,
        domains: Iterable[str] = ("docs", "media"),
        owner_scopes: Iterable[str] = ("personal", "business"),
        max_sensitivity: str = "restricted-pii",
        top_k: int = 5,
        suppress_restricted_pii: bool = True,
        redact_sensitive: bool = True,
        ocr_db: Path = DEFAULT_OCR_DB,
        media_db: Path = DEFAULT_MEDIA_DB,
        inventory_db: Path = DEFAULT_INVENTORY_DB,
    ) -> List[DocChunk]:
        """
        Query private_ocr_index.db and/or stream_media_catalog.db via the
        read-only policy-enforced local intelligence gateway.
        """
        if search_local_intelligence is None:
            raise RuntimeError("local_intelligence_gateway is unavailable.")

        payload = search_local_intelligence(
            query,
            auth=auth_context,
            domains=domains,
            owner_scopes=owner_scopes,
            max_sensitivity=max_sensitivity,
            limit=top_k,
            suppress_restricted_pii=suppress_restricted_pii,
            redact_sensitive=redact_sensitive,
            ocr_db=ocr_db,
            media_db=media_db,
            inventory_db=inventory_db,
        )

        chunks: List[DocChunk] = []
        for item in payload.get("results", []):
            meta: Dict[str, Any] = {
                "retrieval_tier": "local_intelligence_gateway",
                "domain": item.get("domain"),
                "sha256": item.get("sha256"),
                "media_id": item.get("media_id"),
                "filename": item.get("filename"),
                "owner_scope": item.get("owner_scope"),
                "sensitivity_tier": item.get("sensitivity_tier"),
                "category": item.get("category"),
                "location": item.get("location", {}),
                "redacted": bool(item.get("redacted", False)),
                "provenance": item.get("provenance", {}),
            }
            chunks.append(
                DocChunk(
                    text=item.get("snippet", ""),
                    source=item.get("source_path") or item.get("filename") or "unknown",
                    score=float(item.get("rrf_score", 0.0)),
                    metadata=meta,
                )
            )
        return chunks

    async def index(self, directory: str) -> IndexResult:
        """Index documents from a directory into ChromaDB."""
        result = self.rag.index_personal_documents(directory)
        return IndexResult(
            indexed=result.get("indexed_count", result.get("indexed", 0)),
            failed=result.get("failed_count", result.get("failed", 0)),
            errors=result.get("errors", []),
        )

    async def add_document(self, text: str, metadata: Dict[str, Any]) -> bool:
        """Add a single document to the ChromaDB index."""
        return self.rag.add_document(text, metadata)

    def get_stats(self) -> Dict[str, Any]:
        """Get ChromaDB index statistics."""
        return self.rag.get_stats()

    def rebuild_index(self) -> bool:
        """Rebuild the entire ChromaDB index."""
        return self.rag.rebuild_index()
