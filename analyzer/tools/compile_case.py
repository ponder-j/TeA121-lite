"""Compile a C case to normalized LLVM IR when LLVM 15 is available.

The command never invokes a shell and reports a structured failure when the
toolchain is absent, making it safe to use from an evaluation runner.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()
    clang = shutil.which("clang-15") or shutil.which("clang")
    if not clang:
        print(json.dumps({"status": "unsupported", "code": "LLVM_TOOLCHAIN_MISSING", "message": "clang-15/clang is not installed"}))
        return 2
    command = [clang, "-S", "-emit-llvm", "-O0", "-Xclang", "-disable-O0-optnone", str(args.source), "-o", str(args.output)]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode:
        print(json.dumps({"status": "error", "code": "COMPILE_FAILED", "message": completed.stderr.strip(), "command": command}))
        return completed.returncode
    print(json.dumps({"status": "succeeded", "output": str(args.output), "command": command}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
