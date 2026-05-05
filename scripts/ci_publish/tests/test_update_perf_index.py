"""Tests for update_perf_index.py — the R2 index RMW logic."""
import json
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "update_perf_index.py"


def run_updater(tmp_path, *, index, new_files, commit, ts, run_type):
    """Invoke update_perf_index.py with given inputs, return (new_index, orphans)."""
    idx_path = tmp_path / "index.in.json"
    out_path = tmp_path / "index.out.json"
    orphans_path = tmp_path / "orphans.txt"
    files_dir = tmp_path / "ci_bench_results"
    files_dir.mkdir()
    for fname in new_files:
        (files_dir / fname).write_text("{}")
    idx_path.write_text(json.dumps(index))

    subprocess.run(
        [
            "python3", str(SCRIPT),
            "--index", str(idx_path),
            "--new-files-dir", str(files_dir),
            "--commit", commit,
            "--timestamp", ts,
            "--type", run_type,
            "--output", str(out_path),
            "--orphans", str(orphans_path),
        ],
        check=True,
    )
    new_index = json.loads(out_path.read_text())
    orphans = [l for l in orphans_path.read_text().splitlines() if l.strip()]
    return new_index, orphans


def test_inserts_new_entry_into_empty_index(tmp_path):
    new_index, orphans = run_updater(
        tmp_path,
        index=[],
        new_files=["raw_throughput_20260505_120000.json", "failover_20260505_120100.json"],
        commit="abc1234",
        ts="2026-05-05T12:01:00Z",
        run_type="push",
    )
    assert len(new_index) == 1
    entry = new_index[0]
    assert entry["commit"] == "abc1234"
    assert entry["timestamp"] == "2026-05-05T12:01:00Z"
    assert entry["type"] == "push"
    assert sorted(entry["files"]) == sorted([
        "raw_throughput_20260505_120000.json",
        "failover_20260505_120100.json",
    ])
    assert orphans == []


def test_caps_index_at_100_entries(tmp_path):
    """When existing index already has 100 entries, oldest is dropped after insert."""
    existing_entries = [
        {
            "commit": f"old{i:04d}",
            "timestamp": f"2026-01-{(i % 28) + 1:02d}T00:00:00Z",
            "type": "push",
            "files": [f"raw_throughput_old_{i}.json"],
        }
        for i in range(100)
    ]
    new_index, orphans = run_updater(
        tmp_path,
        index=existing_entries,
        new_files=["raw_throughput_new.json"],
        commit="newcomm",
        ts="2026-05-05T12:00:00Z",
        run_type="push",
    )
    assert len(new_index) == 100
    assert new_index[0]["commit"] == "newcomm"
    # The oldest (index 99 in original = old0099) was dropped
    assert "raw_throughput_old_99.json" in orphans
    assert "raw_throughput_new.json" not in orphans
