"""Safe toolchain discovery used before spawning analyzer subprocesses."""

import shutil
from dataclasses import dataclass
from pathlib import Path

from app.config import settings


@dataclass(frozen=True)
class ToolchainStatus:
    analyzer: str | None
    clang: str | None
    extractor: str | None
    optimizer: str | None

    @property
    def available(self) -> bool:
        return self.analyzer is not None


def inspect_toolchain() -> ToolchainStatus:
    analyzer_parts = settings.analyzer_command.split()
    analyzer = shutil.which(analyzer_parts[0]) if analyzer_parts else None
    if analyzer is None and analyzer_parts:
        local = (
            Path(__file__).resolve().parents[3] / "backend" / ".venv" / "bin" / analyzer_parts[0]
        )
        analyzer = str(local) if local.exists() else None
    return ToolchainStatus(
        analyzer=analyzer,
        clang=shutil.which("clang-15") or shutil.which("clang"),
        extractor=shutil.which("tea121-extract"),
        optimizer=shutil.which("opt-15") or shutil.which("opt"),
    )
