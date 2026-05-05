#!/usr/bin/env python3
"""Read-modify-write the perf-data index.json on R2.

Adds a new entry for newly produced JSON files, caps history to top 100 entries,
and emits the list of files no longer referenced (orphans) for caller deletion.
"""
import argparse
import json
import os
from pathlib import Path

MAX_ENTRIES = 100


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--index", required=True, help="Path to current index.json (JSON array)")
    p.add_argument("--new-files-dir", required=True, help="Dir of *.json files to register")
    p.add_argument("--commit", required=True)
    p.add_argument("--timestamp", required=True, help="ISO-8601 UTC timestamp")
    p.add_argument("--type", required=True, choices=["push", "weekly"])
    p.add_argument("--output", required=True, help="Where to write the new index")
    p.add_argument("--orphans", required=True, help="Where to write orphan filenames (one per line)")
    args = p.parse_args()

    with open(args.index) as f:
        index = json.load(f)

    existing = set()
    for e in index:
        existing.update(e.get("files", []))

    files_dir = Path(args.new_files_dir)
    new_files = sorted(
        os.path.basename(f.name)
        for f in files_dir.glob("*.json")
        if f.name != "index.json" and f.name not in existing
    )

    if new_files:
        index.insert(0, {
            "commit": args.commit,
            "timestamp": args.timestamp,
            "type": args.type,
            "files": new_files,
        })

    trimmed = index[:MAX_ENTRIES]

    indexed_now = set()
    for e in trimmed:
        indexed_now.update(e.get("files", []))

    orphans = sorted(existing - indexed_now)

    with open(args.output, "w") as f:
        json.dump(trimmed, f, indent=2)

    with open(args.orphans, "w") as f:
        for o in orphans:
            f.write(o + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
