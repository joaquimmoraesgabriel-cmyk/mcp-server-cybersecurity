from __future__ import annotations

import os
from pathlib import Path


def resolve_data_dir(value: str | Path | None = None) -> Path:
    if value is not None:
        return Path(value).expanduser().resolve()
    if os.environ.get("CYBER_RAG_DATA_DIR"):
        return Path(os.environ["CYBER_RAG_DATA_DIR"]).expanduser().resolve()
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".local" / "share")))
    return (base / "cyber-rag-mcp").resolve()
