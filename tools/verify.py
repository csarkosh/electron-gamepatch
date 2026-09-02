#!/usr/bin/env python3
"""Prove a gamepatch build did exactly what it declared, and nothing else.

1. Disassembly: each patched site reads as the instructions the patch declares.
2. Diff budget: the patched binary differs from upstream only inside declared sites
   (the code-signature blob at the end of the file is excluded: re-signing rewrites it;
   the LC_CODE_SIGNATURE load command itself is also excluded: re-signing can change its
   dataoff/datasize fields, which live in the header before the blob starts).
3. Launch smoke: the patched Electron starts and reports its version.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

_INSN = re.compile(r"^\s*[0-9a-f]+:\s+[0-9a-f]{8}\s+(.*)$")


def log(msg: str) -> None:
    print(f"[verify] {msg}", file=sys.stderr, flush=True)


def normalize_disasm(objdump_output: str) -> list[str]:
    """['mov w0, #0x0', 'ret'] from llvm-objdump text: mnemonic + operands, comments stripped."""
    out = []
    for line in objdump_output.splitlines():
        m = _INSN.match(line)
        if m:
            text = m.group(1).split(";")[0]
            out.append(" ".join(text.replace("\t", " ").split()))
    return out


def disassemble(binary: Path, start: int, end: int) -> list[str]:
    cmd = ["xcrun", "llvm-objdump", "-d", f"--start-address={start:#x}", f"--stop-address={end:#x}", str(binary)]
    return normalize_disasm(subprocess.run(cmd, check=True, text=True, capture_output=True).stdout)


def code_signature_range(otool_output: str) -> tuple[int, int] | None:
    m = re.search(r"cmd LC_CODE_SIGNATURE\n\s+cmdsize \d+\n\s+dataoff (\d+)\n\s+datasize (\d+)", otool_output)
    return (int(m.group(1)), int(m.group(1)) + int(m.group(2))) if m else None


def load_command_ranges(header: bytes, cmd: int = 0x1D) -> list[tuple[int, int]]:
    """The [start, end) byte range of every load command whose `cmd` field equals `cmd`.

    Parses a 64-bit Mach-O header (magic 0xfeedfacf): ncmds at offset 16, load commands
    starting at offset 32, each beginning with two little-endian uint32s (cmd, cmdsize).
    LC_CODE_SIGNATURE is 0x1d. Returns [] if `header` does not start with the 64-bit magic.
    """
    if len(header) < 32 or struct.unpack_from("<I", header, 0)[0] != 0xFEEDFACF:
        return []
    ncmds = struct.unpack_from("<I", header, 16)[0]
    ranges = []
    offset = 32
    for _ in range(ncmds):
        if offset + 8 > len(header):
            break
        lc_cmd, cmdsize = struct.unpack_from("<2I", header, offset)
        if lc_cmd == cmd:
            ranges.append((offset, offset + cmdsize))
        offset += cmdsize
    return ranges


def differing_ranges(a: bytes, b: bytes) -> list[tuple[int, int]]:
    """Half-open [start, end) ranges where a and b differ, over their common length."""
    ranges: list[tuple[int, int]] = []
    start = None
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            if start is None:
                start = i
        elif start is not None:
            ranges.append((start, i))
            start = None
    if start is not None:
        ranges.append((start, min(len(a), len(b))))
    return ranges


def ranges_within(diffs: list[tuple[int, int]], allowed: list[tuple[int, int]]) -> bool:
    return all(any(s >= a and e <= b for a, b in allowed) for s, e in diffs)


def check_sites(stock_bin: Path, patched_bin: Path, sites: list[dict]) -> None:
    for site in sites:
        start, end = site["offset"], site["offset"] + site["length"]
        got = disassemble(patched_bin, start, end)
        if got != site["asm"]:
            raise SystemExit(f"{site['symbol']} @ {start:#x}: disassembles to {got}, expected {site['asm']}")
        log(f"{site['symbol']} @ {start:#x}: {' ; '.join(got)}  OK")

    a, b = stock_bin.read_bytes(), patched_bin.read_bytes()
    otool = subprocess.run(["otool", "-l", str(stock_bin)], check=True, text=True, capture_output=True).stdout
    sig = code_signature_range(otool)
    limit = sig[0] if sig else min(len(a), len(b))
    diffs = differing_ranges(a[:limit], b[:limit])
    allowed = [(s["offset"], s["offset"] + s["length"]) for s in sites]
    allowed += load_command_ranges(a, cmd=0x1D)
    if not ranges_within(diffs, allowed):
        stray = [d for d in diffs if not ranges_within([d], allowed)]
        raise SystemExit(f"{patched_bin.name}: bytes differ outside declared sites: {[(f'{s:#x}', f'{e:#x}') for s, e in stray[:10]]}")
    log(f"{patched_bin.name}: {len(diffs)} differing range(s), all inside declared sites; code signature excluded from {limit:#x}")


def launch_smoke(app: Path, version: str) -> None:
    exe = app / "Contents/MacOS/Electron"
    out = subprocess.run([str(exe), "--version"], check=True, text=True, capture_output=True, timeout=60).stdout.strip()
    if out != f"v{version}":
        raise SystemExit(f"{exe}: --version printed {out!r}, expected 'v{version}'")
    log(f"launch smoke: {out}  OK")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--version", required=True)
    ap.add_argument("--platform", required=True)
    ap.add_argument("--work", type=Path, default=Path("work"))
    ap.add_argument("--dist", type=Path, default=Path("dist"))
    a = ap.parse_args(argv)
    record = json.loads((a.dist / f"electron-v{a.version}-{a.platform}.patches.json").read_text())
    stock, patched = a.work / a.platform / "stock", a.work / a.platform / "patched"
    by_binary: dict[str, list[dict]] = {}
    for patch in record["patches"]:
        by_binary.setdefault(patch["binary"], []).extend(patch["sites"])
    for rel, sites in by_binary.items():
        check_sites(stock / rel, patched / rel, sites)
    launch_smoke(patched / "Electron.app", a.version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
