#!/usr/bin/env python3
"""Which upstream Electron versions to republish.

Rule: track the highest stable major upstream has released. If we have nothing on that major,
build only its latest release; otherwise build every release on it newer than our newest.
Prereleases (any tag containing '-') are ignored on both sides.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_STABLE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def parse_version(tag: str) -> tuple[int, int, int]:
    m = _STABLE.match(tag.strip())
    if not m:
        raise ValueError(f"not a stable tag: {tag!r}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _stable(tags: list[str]) -> list[tuple[int, int, int]]:
    return sorted(parse_version(t) for t in tags if _STABLE.match(t.strip()))


def versions_to_build(upstream_tags: list[str], our_tags: list[str]) -> list[str]:
    upstream = _stable(upstream_tags)
    if not upstream:
        return []
    major = upstream[-1][0]
    line = [v for v in upstream if v[0] == major]
    ours = [v for v in _stable(our_tags) if v[0] == major]
    wanted = [v for v in line if v > ours[-1]] if ours else line[-1:]
    return [".".join(map(str, v)) for v in wanted]


def main(argv: list[str]) -> int:
    upstream = Path(argv[1]).read_text().split()
    ours = Path(argv[2]).read_text().split() if len(argv) > 2 and Path(argv[2]).exists() else []
    print(json.dumps(versions_to_build(upstream, ours)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
