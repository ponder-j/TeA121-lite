"""Process-level bridge from C/LLVM files to MiniIR.

Compilation is deliberately kept outside the analysis engine. Commands are
passed as argument arrays and all intermediate files live in a private temp
directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from tea121.ir import load_module


class FrontendError(RuntimeError):
    def __init__(self, code: str, message: str, severity: str = "unsupported", impact: str | None = None):
        super().__init__(message)
        self.code = code
        self.severity = severity
        self.impact = impact or message


def load_input(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    if suffix in {".json", ".miniir"}:
        return load_module(path)
    extractor = os.environ.get("TEA121_EXTRACTOR") or shutil.which("tea121-extract")
    if not extractor:
        raise FrontendError("LLVM_FRONTEND_UNAVAILABLE", "tea121-extract is not installed", impact="install LLVM 15 and build the extractor or use the tea121 Docker image")
    clang = os.environ.get("TEA121_CLANG") or shutil.which("clang-15") or shutil.which("clang")
    if suffix in {".c", ".cc", ".cpp", ".cxx"} and not clang:
        raise FrontendError("LLVM_TOOLCHAIN_MISSING", "clang-15/clang is not installed", impact="use docker compose run analyzer for a reproducible LLVM 15 toolchain")
    with tempfile.TemporaryDirectory(prefix="tea121-") as directory:
        raw_ir_path = Path(directory) / "raw.ll"
        ir_path = Path(directory) / "normalized.ll"
        if suffix in {".c", ".cc", ".cpp", ".cxx"}:
            command = [clang, "-S", "-emit-llvm", "-O0", "-Xclang", "-disable-O0-optnone", "-g", str(path), "-o", str(raw_ir_path)]
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            if completed.returncode:
                raise FrontendError("COMPILE_FAILED", completed.stderr.strip() or "clang failed to compile input", severity="error")
        elif suffix != ".ll":
            raise FrontendError("INPUT_FORMAT_UNSUPPORTED", f"unsupported input suffix: {suffix}")
        else:
            raw_ir_path = path
        optimizer = os.environ.get("TEA121_OPT") or shutil.which("opt-15") or shutil.which("opt")
        if optimizer:
            normalized = subprocess.run([optimizer, "-S", "-passes=mem2reg", str(raw_ir_path), "-o", str(ir_path)], capture_output=True, text=True, check=False)
            if normalized.returncode:
                raise FrontendError("NORMALIZATION_FAILED", normalized.stderr.strip() or "opt mem2reg failed", severity="error")
        else:
            ir_path = raw_ir_path
        output = Path(directory) / "module.json"
        completed = subprocess.run([extractor, str(ir_path), "-o", str(output)], capture_output=True, text=True, check=False)
        if completed.returncode:
            raise FrontendError("EXTRACTION_FAILED", completed.stderr.strip() or "LLVM extractor failed", severity="error")
        try:
            module = load_module(json.loads(output.read_text(encoding="utf-8")))
            normalized_ir = ir_path.read_text(encoding="utf-8")
            module["_artifacts"] = [
                {
                    "kind": "normalized_ir",
                    "content": normalized_ir,
                    "sha256": hashlib.sha256(normalized_ir.encode()).hexdigest(),
                }
            ]
            return module
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise FrontendError("INVALID_MINIIR", str(exc), severity="error") from exc
