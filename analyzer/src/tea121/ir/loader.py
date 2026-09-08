"""Small, versioned MiniIR loader.

The solver intentionally consumes plain dictionaries so fixtures remain easy to
author and the LLVM extractor can evolve independently.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SUPPORTED_SCHEMA = {"1.0", "1.0.0"}


def load_module(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    if isinstance(source, dict):
        module = source
    else:
        module = json.loads(Path(source).read_text(encoding="utf-8"))
    version = str(module.get("schema_version", ""))
    if version not in SUPPORTED_SCHEMA:
        raise ValueError(f"unsupported MiniIR schema_version: {version!r}")
    if not isinstance(module.get("functions", []), list):
        raise ValueError("MiniIR functions must be an array")
    return module
