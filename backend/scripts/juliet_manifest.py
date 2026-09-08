"""Discover Juliet cases and emit an Evaluation API request body.

This script only builds a deterministic manifest. The analyzer's own Juliet
runner remains responsible for compilation semantics and outcome generation.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

PATTERN = re.compile(
    r"^(?P<base>.+)_(?P<flow>\d{2})(?P<part>[a-z])?(?P<role>_(?:bad|goodB2G|goodG2B))?\.(?:c|cc|cpp|cxx)$"
)


def discover(root: Path, flow: str | None = None, limit: int | None = None) -> list[dict]:
    groups: dict[tuple[str, str], list[Path]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        match = PATTERN.match(path.name)
        if not match or (flow and match.group("flow") != flow):
            continue
        groups.setdefault((match.group("base"), match.group("flow")), []).append(path)
    cases = []
    for (base, number), paths in sorted(groups.items()):
        bad_files = []
        good_files = []
        for path in paths:
            filename = path.name
            if "_goodB2G" in filename or "_goodG2B" in filename:
                good_files.append(str(path))
            elif "_bad" in filename:
                bad_files.append(str(path))
            else:
                bad_files.append(str(path))
                good_files.append(str(path))
        cases.append(
            {
                "case_name": f"{base}_{number}",
                "cwe_id": "CWE-121",
                "family": base.rsplit("__", 1)[-1] if "__" in base else None,
                "bad_files": bad_files,
                "good_files": good_files,
                "files": [
                    {"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                    for p in paths
                ],
            }
        )
        if limit is not None and len(cases) >= limit:
            break
    return cases


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--flow")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    cases = discover(args.root, args.flow, args.limit)
    payload = {
        "dataset_name": "Juliet CWE-121",
        "dataset_version": hashlib.sha256(json.dumps(cases, sort_keys=True).encode()).hexdigest()[
            :16
        ],
        "detector_id": "stack-bounds",
        "rule_pack_id": "cwe121-core",
        "filter": {"flow": args.flow},
        "cases": cases,
    }
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {len(cases)} cases to {args.output}")


if __name__ == "__main__":
    main()
