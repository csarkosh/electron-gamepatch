#!/usr/bin/env python3
"""Prove a gamepatch build did exactly what it declared, and nothing else.

1. Disassembly: each patched site reads as the instructions the patch declares.
2. Diff budget: the patched binary differs from upstream only inside declared sites
   (the code-signature blob at the end of the file is excluded: re-signing rewrites it;
   the LC_CODE_SIGNATURE load command itself is also excluded, since re-signing can change
   its dataoff/datasize fields, which live in the header before the blob starts; and the
   __LINKEDIT LC_SEGMENT_64 command's vmsize/filesize fields are excluded, since a shrunk
   ad-hoc signature shrinks the segment codesign declares it lives in).
3. Signature: the patched binary's signature verifies, on a scratch copy outside the bundle
   (codesign refuses to verify a framework's main executable in place: it treats the path as
   the bundle and complains the bundle has no sealed resources).
4. Launch smoke: the patched Electron starts and reports its version.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

_INSN = re.compile(r"^\s*[0-9a-f]+:\s+[0-9a-f]{8}\s+(.*)$")
_IMMEDIATE = re.compile(r"#(-?)(0x[0-9a-fA-F]+|\d+)")


def log(msg: str) -> None:
    print(f"[verify] {msg}", file=sys.stderr, flush=True)


def _canonicalize_immediate(m: re.Match) -> str:
    sign, value = m.group(1), m.group(2)
    return f"#{sign}0x{int(value, 0):x}"


def normalize_disasm(objdump_output: str) -> list[str]:
    """['mov w0, #0x0', 'ret'] from llvm-objdump text: mnemonic + operands, comments stripped,
    immediates canonicalized to lowercase hex (`#0` and `#0x0` both become `#0x0`) so the same
    instruction compares equal across llvm-objdump versions that spell immediates differently."""
    out = []
    for line in objdump_output.splitlines():
        m = _INSN.match(line)
        if m:
            text = m.group(1).split(";")[0]
            text = " ".join(text.replace("\t", " ").split())
            out.append(_IMMEDIATE.sub(_canonicalize_immediate, text))
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


def codesign_owned_ranges(header: bytes) -> list[tuple[int, int]]:
    """Byte ranges in a Mach-O header that `codesign --force` may legitimately rewrite.

    - The whole LC_CODE_SIGNATURE (0x1d) command: re-signing can change its dataoff/datasize.
    - Inside the LC_SEGMENT_64 (0x19) command for segname "__LINKEDIT": only the 8-byte vmsize
      field (command offset 32-40) and the 8-byte filesize field (command offset 48-56).
      segment_command_64 layout: cmd(4) cmdsize(4) segname(16) vmaddr(8) vmsize(8) fileoff(8)
      filesize(8) ... . A shrunk ad-hoc signature shrinks __LINKEDIT's declared size, but must
      not license a diff anywhere else in that command (segname, vmaddr, fileoff, section list).
    """
    ranges = list(load_command_ranges(header, cmd=0x1D))
    for start, end in load_command_ranges(header, cmd=0x19):
        segname = header[start + 8 : start + 24].rstrip(b"\x00")
        if segname == b"__LINKEDIT":
            ranges.append((start + 32, start + 40))  # vmsize
            ranges.append((start + 48, start + 56))  # filesize
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
    allowed += codesign_owned_ranges(a)
    if not ranges_within(diffs, allowed):
        stray = [d for d in diffs if not ranges_within([d], allowed)]
        raise SystemExit(f"{patched_bin.name}: bytes differ outside declared sites: {[(f'{s:#x}', f'{e:#x}') for s, e in stray[:10]]}")
    log(f"{patched_bin.name}: {len(diffs)} differing range(s), all inside declared sites; code signature excluded from {limit:#x}")


def signature_valid(binary: Path) -> None:
    """`codesign --verify --strict` at the in-bundle path fails even on an untouched, never
    re-signed binary: codesign treats a framework's designated main executable as the bundle
    itself and refuses ("code has no resources but signature indicates they must be
    present"), since the file next to it isn't sealed the way a `--deep`-signed bundle would
    be. Verify on a copy in a scratch directory with no bundle context instead — the same
    technique `gamepatch.codesign_adhoc` uses to sign it — so this actually checks the bytes
    that get copied back into the shipped zip."""
    scratch = Path(tempfile.mkdtemp(prefix="verify-sig-"))
    try:
        tmp = scratch / binary.name
        shutil.copyfile(binary, tmp)
        result = subprocess.run(["codesign", "--verify", "--strict", str(tmp)], text=True, capture_output=True)
        if result.returncode != 0:
            raise SystemExit(f"{binary.name}: signature invalid: {result.stderr}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    log(f"signature (shipped bytes): {binary.name}  OK")


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
    for rel in by_binary:
        signature_valid(patched / rel)
    launch_smoke(patched / "Electron.app", a.version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
