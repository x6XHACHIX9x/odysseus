"""Hardware-tier presets for local Deep Research runs (small, medium, large)."""

from copy import deepcopy
from typing import Any, Dict, Optional

ALLOWED_HARDWARE_PRESETS = ("small", "medium", "large")

RESEARCH_HARDWARE_PRESETS: Dict[str, Dict[str, Any]] = {
    "small": {
        "id": "small",
        "label": "Small (8 GB VRAM / 4B-8B)",
        "description": "Low-VRAM and CPU-offload systems: shorter context chunks, sequential extraction, and compact round caps.",
        "recommended_models": ["qwen3:8b", "gemma4:e4b", "llama3.1:8b"],
        "max_rounds": 4,
        "min_rounds": 2,
        "max_time": 240,
        "max_urls_per_round": 2,
        "max_content_chars": 8000,
        "max_report_tokens": 4096,
        "extraction_timeout": 120,
        "planning_timeout": 90,
        "query_timeout": 90,
        "extraction_concurrency": 1,
        "synthesis_window": 6,
    },
    "medium": {
        "id": "medium",
        "label": "Medium (16-24 GB VRAM / 14B-32B)",
        "description": "Single workstation GPU (RTX 4080/4090/5090 or 24-32 GB Apple Silicon): balanced depth, concurrency, and report length.",
        "recommended_models": ["gemma4:31b", "qwen3:32b", "gpt-oss:20b"],
        "max_rounds": 8,
        "min_rounds": 3,
        "max_time": 420,
        "max_urls_per_round": 3,
        "max_content_chars": 15000,
        "max_report_tokens": 8192,
        "extraction_timeout": 120,
        "planning_timeout": 120,
        "query_timeout": 120,
        "extraction_concurrency": 3,
        "synthesis_window": 10,
    },
    "large": {
        "id": "large",
        "label": "Large (48+ GB VRAM / 70B+)",
        "description": "High-VRAM workstation or multi-GPU server: wide multi-source synthesis, higher concurrency, and long-form reports.",
        "recommended_models": ["llama3.3:70b", "qwen3:72b", "gpt-oss:120b"],
        "max_rounds": 14,
        "min_rounds": 4,
        "max_time": 720,
        "max_urls_per_round": 5,
        "max_content_chars": 24000,
        "max_report_tokens": 16384,
        "extraction_timeout": 150,
        "planning_timeout": 150,
        "query_timeout": 150,
        "extraction_concurrency": 5,
        "synthesis_window": 16,
    },
}


def normalize_hardware_preset(preset: Optional[str]) -> Optional[str]:
    """Validate and normalize a hardware preset name ('small' | 'medium' | 'large')."""
    if preset is None:
        return None
    val = str(preset).strip().lower()
    if not val or val == "auto":
        return None
    if val not in RESEARCH_HARDWARE_PRESETS:
        raise ValueError(f"Unsupported hardware preset: {preset}")
    return val


def get_research_preset(preset: Optional[str]) -> Optional[Dict[str, Any]]:
    """Return a deep copy of the named hardware preset, or None if unset/auto."""
    key = normalize_hardware_preset(preset)
    if key is None:
        return None
    return deepcopy(RESEARCH_HARDWARE_PRESETS[key])


def list_research_presets() -> list[Dict[str, Any]]:
    """Return ordered preset metadata for API and UI consumption."""
    return [deepcopy(RESEARCH_HARDWARE_PRESETS[k]) for k in ALLOWED_HARDWARE_PRESETS]
