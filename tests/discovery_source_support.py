# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — discovery source validation
"""Create real neutral discovery captures for public API and CLI tests."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from typing import cast

from rigor_foundry.discovery_source_schema import SCHEMA, DiscoveryLimits


def encode(value: object) -> bytes:
    """Serialize test inputs deterministically, preserving explicit escapes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(payload: bytes) -> str:
    """Compute an independent standard-library exact-byte digest."""
    return hashlib.sha256(payload).hexdigest()


def snapshot(root: Path) -> dict[str, object]:
    """Create two real sources and shards plus one unused empty inventory source."""
    sources = []
    shards = []
    for index, payload in enumerate((b"First\r\nSecond\n", "Živý text\nLast".encode(), b"")):
        capture = f"source{index}.txt"
        (root / capture).write_bytes(payload)
        sources.append(
            {
                "source_id": f"source{index}",
                "capture": capture,
                "sha256": sha(payload),
                "bytes": len(payload),
                "lines": 2 if payload else 0,
            }
        )
        if not payload:
            continue
        shard = {
            "schema_version": SCHEMA,
            "status": "discovery-only",
            "shard_id": f"shard{index}",
            "candidates": [
                {
                    "candidate_id": f"rule{index}",
                    "statement": 'Retain "source" evidence.',
                    "source_spans": [
                        {
                            "source_id": f"source{index}",
                            "start_line": 1,
                            "end_line": 2,
                            "sha256": sha(payload),
                        }
                    ],
                }
            ],
        }
        raw = encode(shard)
        capture = f"shard{index}.json"
        (root / capture).write_bytes(raw)
        shards.append(
            {
                "shard_id": f"shard{index}",
                "capture": capture,
                "sha256": sha(raw),
                "bytes": len(raw),
                "candidates": 1,
            }
        )
    manifest: dict[str, object] = {
        "schema_version": SCHEMA,
        "status": "discovery-only",
        "sources": sources,
        "shards": shards,
        "candidate_count": 2,
    }
    write_manifest(root, manifest)
    return manifest


def write_manifest(root: Path, manifest: dict[str, object]) -> None:
    """Persist a complete test manifest after one explicit mutation."""
    (root / "manifest.json").write_bytes(encode(manifest))


def records(manifest: dict[str, object], key: str) -> list[dict[str, object]]:
    """Expose typed test-owned source or shard records for focused mutations."""
    return cast(list[dict[str, object]], manifest[key])


def load_shard(root: Path, index: int = 0) -> dict[str, object]:
    """Read a real captured shard before a schema-boundary mutation."""
    return cast(dict[str, object], json.loads((root / f"shard{index}.json").read_bytes()))


def write_shard(
    root: Path, manifest: dict[str, object], shard: dict[str, object], index: int = 0
) -> None:
    """Rebind a deliberately mutated shard so inner validation is exercised."""
    raw = encode(shard)
    (root / f"shard{index}.json").write_bytes(raw)
    record = records(manifest, "shards")[index]
    record["bytes"], record["sha256"] = len(raw), sha(raw)
    write_manifest(root, manifest)


def limits(root: Path, **overrides: int) -> DiscoveryLimits:
    """Set exact fixture resource counts and actual complete on-disk byte sizes."""
    files = [
        root / name
        for name in (
            "manifest.json",
            "source0.txt",
            "source1.txt",
            "source2.txt",
            "shard0.json",
            "shard1.json",
        )
    ]
    sizes = [path.lstat().st_size for path in files]
    values = {
        "total_bytes": sum(sizes),
        "file_bytes": max(sizes),
        "sources": 3,
        "shards": 2,
        "candidates": 2,
        "spans": 2,
    }
    values.update(overrides)
    return DiscoveryLimits(**values)


def arguments(root: Path, budget: DiscoveryLimits) -> list[str]:
    """Build explicit CLI arguments without shell expansion or implicit budgets."""
    result = ["--root", str(root), "--manifest", "manifest.json"]
    for name, value in asdict(budget).items():
        result.extend(["--max-" + name.replace("_", "-"), str(value)])
    return result


def cli(
    root: Path, budget: DiscoveryLimits, extra: list[str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run the actual module CLI with a bounded lifetime and selected worktree."""
    environment = {
        **os.environ,
        "PYTHONPATH": str(Path(__file__).parents[1] / "src"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "rigor_foundry.discovery_source_cli",
            *arguments(root, budget),
            *(extra or []),
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
