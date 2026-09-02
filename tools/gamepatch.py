#!/usr/bin/env python3
"""electron-gamepatch engine: apply declarative byte patches to official Electron releases.

Pure functions first (tested in tests/test_gamepatch.py), then the IO layer and CLI.
Stdlib only.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable, Iterable

# Breakpad: "FUNC [m] <address> <size> <parameter_size> <name>"
_FUNC = re.compile(r"^FUNC (?:m )?([0-9a-fA-F]+) ([0-9a-fA-F]+) [0-9a-fA-F]+ (.+)$")


def parse_sym(lines: Iterable[str]) -> tuple[str, dict[str, list[tuple[int, int]]]]:
    """Return (module_id, {function name: [(address, size), ...]}) from a Breakpad .sym stream.

    Streams line by line: a framework .sym is over a gigabyte, most of it line records.
    """
    module_id = None
    funcs: dict[str, list[tuple[int, int]]] = {}
    for line in lines:
        if line.startswith("FUNC "):
            m = _FUNC.match(line.rstrip("\n"))
            if m:
                funcs.setdefault(m.group(3), []).append((int(m.group(1), 16), int(m.group(2), 16)))
        elif module_id is None and line.startswith("MODULE "):
            module_id = line.split()[3]
    if module_id is None:
        raise ValueError("not a Breakpad .sym file: no MODULE line")
    return module_id, funcs


def resolve_symbol(funcs: dict[str, list[tuple[int, int]]], name: str) -> tuple[int, int]:
    """The (address, size) of exactly one FUNC named `name`."""
    matches = funcs.get(name, [])
    if len(matches) != 1:
        found = ", ".join(f"{a:#x}+{s:#x}" for a, s in matches) or "none"
        raise LookupError(f"{name!r}: expected exactly one FUNC, found {len(matches)} ({found})")
    return matches[0]


def apply_sites(data: bytearray, sites: list[dict], resolve: Callable[[str], tuple[int, int]]) -> list[dict]:
    """Patch every site into `data` (file offsets == symbol addresses) and return a record per site.

    Every site is checked before any byte is written, so a bad `expect` leaves `data` untouched.
    """
    planned = []
    for site in sites:
        expect, write = bytes.fromhex(site["expect"]), bytes.fromhex(site["write"])
        if len(expect) != len(write):
            raise ValueError(f"{site['symbol']}: expect ({len(expect)} B) and write ({len(write)} B) differ in length")
        address, size = resolve(site["symbol"])
        offset = address + int(site.get("offset", 0))
        if offset + len(expect) > address + size:
            raise ValueError(f"{site['symbol']}: site {offset:#x}+{len(expect)} exceeds function {address:#x}+{size:#x}")
        found = bytes(data[offset : offset + len(expect)])
        if found != expect:
            raise ValueError(f"{site['symbol']} @ {offset:#x}: found {found.hex()}, expected {expect.hex()}")
        planned.append((site, offset, expect, write))
    records = []
    for site, offset, expect, write in planned:
        data[offset : offset + len(write)] = write
        records.append({"symbol": site["symbol"], "offset": offset, "length": len(write),
                        "old": expect.hex(), "new": write.hex(), "asm": list(site["asm"])})
    return records


def load_patch(path: Path) -> dict:
    """Read and validate one patches/<name>/patch.json."""
    patch = json.loads(Path(path).read_text())
    for key in ("name", "summary", "targets"):
        if key not in patch:
            raise ValueError(f"{path}: missing {key!r}")
    for platform, target in patch["targets"].items():
        if "binary" not in target or not isinstance(target.get("sites"), list) or not target["sites"]:
            raise ValueError(f"{path}: target {platform!r} needs 'binary' and a non-empty 'sites' list")
        for site in target["sites"]:
            for key in ("symbol", "expect", "write", "asm"):
                if key not in site:
                    raise ValueError(f"{path}: site in {platform!r} missing {key!r}")
            for key in ("expect", "write"):
                if len(site[key]) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", site[key]):
                    raise ValueError(f"{path}: {site['symbol']}: {key!r} is not even-length hex")
            if len(site["expect"]) != len(site["write"]):
                raise ValueError(f"{path}: {site['symbol']}: expect and write differ in length")
            if not isinstance(site["asm"], list) or not site["asm"]:
                raise ValueError(f"{path}: {site['symbol']}: 'asm' must be a non-empty list")
    return patch


def load_patches(root: Path) -> list[dict]:
    return [load_patch(p) for p in sorted(Path(root).glob("*/patch.json"))]


def format_shasums(entries: dict[str, str]) -> str:
    """Upstream's SHASUMS256.txt format: '<sha256> *<filename>' per line, sorted by filename."""
    return "".join(f"{sha} *{name}\n" for name, sha in sorted(entries.items()))


def parse_shasums(text: str) -> dict[str, str]:
    entries = {}
    for line in text.splitlines():
        if line.strip():
            sha, name = line.split(maxsplit=1)
            entries[name.lstrip("*").strip()] = sha
    return entries
