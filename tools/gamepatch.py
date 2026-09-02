#!/usr/bin/env python3
"""electron-gamepatch engine: apply declarative byte patches to official Electron releases.

Pure functions first (tested in tests/test_gamepatch.py), then the IO layer and CLI.
Stdlib only.

patch.json fields: "name", "summary", "targets" (required); "upstream_source" (optional) is
a free-text string naming the Chromium/Electron source file the patch targets, for humans —
not parsed by the engine, but validated non-empty when present.
"""
from __future__ import annotations

import json
import re
import struct
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


def apply_sites(data: bytearray, sites: list[dict], resolve: Callable[[str], tuple[int, int]],
                to_vaddr: Callable[[int], int] = lambda offset: offset) -> list[dict]:
    """Patch every site into `data` and return a record per site.

    `resolve(symbol)` returns (file offset, size) of the function; `to_vaddr(offset)` maps a
    file offset back to the virtual address a disassembler wants (identity for Mach-O, whose
    __TEXT is at vmaddr 0 / fileoff 0; section translation for PE).
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
        records.append({"symbol": site["symbol"], "offset": offset, "vaddr": to_vaddr(offset), "length": len(write),
                        "old": expect.hex(), "new": write.hex(), "asm": list(site["asm"])})
    return records


def load_patch(path: Path) -> dict:
    """Read and validate one patches/<name>/patch.json."""
    patch = json.loads(Path(path).read_text())
    for key in ("name", "summary", "targets"):
        if key not in patch:
            raise ValueError(f"{path}: missing {key!r}")
    if "upstream_source" in patch and (not isinstance(patch["upstream_source"], str) or not patch["upstream_source"]):
        raise ValueError(f"{path}: 'upstream_source' must be a non-empty string")
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


def _pe_headers(data: bytes) -> tuple[int, int, int, int]:
    """(coff_offset, optional_header_offset, number_of_sections, section_table_offset)."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not a PE file: no MZ header")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise ValueError("not a PE file: no PE signature")
    coff = e_lfanew + 4
    try:
        nsections, opt_size = struct.unpack_from("<H", data, coff + 2)[0], struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        if struct.unpack_from("<H", data, opt)[0] != 0x20B:
            raise ValueError("not a PE32+ (64-bit) image")
    except struct.error as e:
        raise ValueError(f"truncated PE: {e}") from e
    return coff, opt, nsections, opt + opt_size


def pe_sections(data: bytes) -> list[dict]:
    """The section table: name, rva, vsize, rawoff, rawsize — in file order."""
    _, _, n, table = _pe_headers(data)
    sections = []
    try:
        for i in range(n):
            o = table + 40 * i
            name = data[o : o + 8].rstrip(b"\0").decode("latin-1")
            vsize, rva, rawsize, rawoff = struct.unpack_from("<IIII", data, o + 8)
            sections.append({"name": name, "rva": rva, "vsize": vsize, "rawoff": rawoff, "rawsize": rawsize})
    except struct.error as e:
        raise ValueError(f"truncated PE: {e}") from e
    return sections


def pe_image_base(data: bytes) -> int:
    _, opt, _, _ = _pe_headers(data)
    try:
        return struct.unpack_from("<Q", data, opt + 24)[0]
    except struct.error as e:
        raise ValueError(f"truncated PE: {e}") from e


def pe_rva_to_offset(sections: list[dict], rva: int) -> int:
    """File offset of a virtual address, through the section that contains it."""
    for s in sections:
        if s["rva"] <= rva < s["rva"] + max(s["vsize"], s["rawsize"]):
            return rva - s["rva"] + s["rawoff"]
    raise ValueError(f"RVA {rva:#x} is not inside any section")


def pe_offset_to_rva(sections: list[dict], offset: int) -> int:
    for s in sections:
        if s["rawoff"] <= offset < s["rawoff"] + s["rawsize"]:
            return offset - s["rawoff"] + s["rva"]
    raise ValueError(f"file offset {offset:#x} is not inside any section")


def pe_codeview_id(data: bytes) -> str:
    """The Breakpad module id of a PE: the RSDS CodeView GUID (first three fields
    byte-swapped, as Breakpad prints them) followed by the age in upper-case hex."""
    _, opt, _, _ = _pe_headers(data)
    try:
        nrva = struct.unpack_from("<I", data, opt + 108)[0]
        if nrva <= 6:
            raise ValueError("no debug directory")
        debug_rva, debug_size = struct.unpack_from("<II", data, opt + 112 + 6 * 8)
        if debug_size == 0:
            raise ValueError("empty debug directory")
        sections = pe_sections(data)
        off = pe_rva_to_offset(sections, debug_rva)
        for i in range(debug_size // 28):
            entry = off + 28 * i
            kind, size, _, raw = struct.unpack_from("<IIII", data, entry + 12)
            if kind != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                continue
            rec = data[raw : raw + size]
            if rec[:4] != b"RSDS":
                raise ValueError("CodeView record is not RSDS")
            d1, d2, d3 = struct.unpack_from("<IHH", rec, 4)
            rest = rec[12:20].hex().upper()
            age = struct.unpack_from("<I", rec, 20)[0]
            return f"{d1:08X}{d2:04X}{d3:04X}{rest}{age:X}"
    except struct.error as e:
        raise ValueError(f"truncated PE: {e}") from e
    raise ValueError("no CodeView entry in the debug directory")


# ---------------------------------------------------------------- IO layer

import argparse
import contextlib
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

UPSTREAM_DOWNLOAD = "https://github.com/electron/electron/releases/download"
UPSTREAM_API = "https://api.github.com/repos/electron/electron/releases/tags"
_PLATFORM_ZIP = re.compile(r"^electron-v(?P<v>[^-]+)-(?P<platform>(darwin|mas|win32|linux)-[a-z0-9]+)\.zip$")


def log(msg: str) -> None:
    print(f"[gamepatch] {msg}", file=sys.stderr, flush=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _request(url: str) -> urllib.request.Request:
    headers = {"User-Agent": "electron-gamepatch"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.Request(url, headers=headers)


def download(url: str, dest: Path) -> Path:
    """Stream `url` to `dest` unless it already exists. Partial downloads never leave a `dest`."""
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    log(f"downloading {url}")
    with urllib.request.urlopen(_request(url)) as r, open(tmp, "wb") as f:
        shutil.copyfileobj(r, f, 1 << 20)
    tmp.rename(dest)
    return dest


def upstream_shasums(version: str, cache: Path) -> dict[str, str]:
    path = download(f"{UPSTREAM_DOWNLOAD}/v{version}/SHASUMS256.txt", cache / f"v{version}" / "SHASUMS256.txt")
    return parse_shasums(path.read_text())


def fetch_upstream(version: str, filename: str, cache: Path) -> Path:
    """Download one upstream release asset into the cache and verify it against upstream's SHASUMS256.txt."""
    expected = upstream_shasums(version, cache).get(filename)
    if expected is None:
        raise LookupError(f"{filename} is not in upstream SHASUMS256.txt for v{version}")
    path = download(f"{UPSTREAM_DOWNLOAD}/v{version}/{filename}", cache / f"v{version}" / filename)
    actual = sha256_file(path)
    if actual != expected:
        path.unlink()
        raise ValueError(f"{filename}: sha256 {actual} != upstream {expected} (deleted; re-run)")
    return path


def upstream_asset_names(release_json: dict, version: str) -> list[str]:
    """The `electron-v<version>-<platform>.zip` assets of an upstream release, sorted."""
    names = [a["name"] for a in release_json.get("assets", [])]
    return sorted(n for n in names if (m := _PLATFORM_ZIP.match(n)) and m.group("v") == version)


def upstream_release(version: str) -> dict:
    with urllib.request.urlopen(_request(f"{UPSTREAM_API}/v{version}")) as r:
        return json.load(r)


def run(*cmd: str, capture: bool = False) -> str:
    log("$ " + " ".join(cmd))
    result = subprocess.run(cmd, check=True, text=True, capture_output=capture)
    return result.stdout if capture else ""


def sym_module_id_from_uuid(uuid: str) -> str:
    """Breakpad MODULE ids are the Mach-O UUID without dashes, upper-case, plus an age digit of 0."""
    return uuid.replace("-", "").upper() + "0"


def macho_uuid(binary: Path) -> str:
    out = run("dwarfdump", "--uuid", str(binary), capture=True)
    m = re.search(r"UUID: ([0-9A-Fa-f-]{36})", out)
    if not m:
        raise ValueError(f"no UUID in dwarfdump output for {binary}")
    return m.group(1)


def text_segment_is_at_zero(otool_output: str) -> bool:
    """True when __TEXT has vmaddr 0 and fileoff 0, i.e. symbol address == file offset."""
    m = re.search(r"segname __TEXT\n\s+vmaddr (0x[0-9a-f]+)\n\s+vmsize 0x[0-9a-f]+\n\s+fileoff (\d+)", otool_output)
    return bool(m) and int(m.group(1), 16) == 0 and int(m.group(2)) == 0


def assert_text_at_zero(binary: Path) -> None:
    if not text_segment_is_at_zero(run("otool", "-l", str(binary), capture=True)):
        raise ValueError(f"{binary}: __TEXT is not at vmaddr 0 / fileoff 0; symbol addresses are not file offsets")


@contextlib.contextmanager
def open_sym(symbols_zip: Path, binary_basename: str):
    """A text stream over `<basename>.sym` inside an upstream symbols zip.

    Context manager: closes both the text stream and the underlying ZipFile on exit.
    """
    zf = zipfile.ZipFile(symbols_zip)
    try:
        wanted = f"/{binary_basename}.sym"
        names = [n for n in zf.namelist() if n.endswith(wanted)]
        if len(names) != 1:
            raise LookupError(f"{symbols_zip.name}: expected one {wanted}, found {names}")
        sym = io.TextIOWrapper(zf.open(names[0]), encoding="utf-8", errors="replace")
        try:
            yield sym
        finally:
            sym.close()
    finally:
        zf.close()


def unzip(zip_path: Path, dest: Path) -> None:
    """`unzip`, not zipfile: the Python module drops symlinks and modes, and Electron.app has both."""
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    run("unzip", "-q", str(zip_path), "-d", str(dest))


def rezip(src_dir: Path, zip_path: Path) -> None:
    """Re-create the upstream zip layout (entries at the root) preserving symlinks (-y) and no extra attrs (-X)."""
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    zip_path.unlink(missing_ok=True)
    entries = sorted(p.name for p in src_dir.iterdir())
    subprocess.run(["zip", "-q", "-r", "-y", "-X", str(zip_path.resolve()), *entries], cwd=src_dir, check=True)


def codesign_adhoc(binaries: list[Path]) -> None:
    """Re-sign only the binaries a patch modified: their linker signature was invalidated by
    the byte change. Signing happens OUTSIDE the bundle tree, on a copy in a scratch
    directory with a plain (non-bundle) path: codesign auto-detects when a path is a
    framework's designated main executable and seals the whole enclosing bundle (adding
    `_CodeSignature/CodeResources`, which upstream's zip does not have) even without `--deep`,
    purely from the binary sitting next to a Resources/Info.plist. Signing a copy that has no
    such neighbours avoids that; the signed bytes (an embedded LC_CODE_SIGNATURE, nothing
    else) are then copied back over the original in place."""
    for binary in binaries:
        mode = binary.stat().st_mode
        scratch = Path(tempfile.mkdtemp(prefix="codesign-"))
        try:
            tmp = scratch / binary.name
            shutil.copyfile(binary, tmp)
            run("codesign", "--force", "--sign", "-", str(tmp))
            run("codesign", "--verify", "--strict", str(tmp))
            shutil.copyfile(tmp, binary)
            os.chmod(binary, mode)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)


class _MachO:
    name, signs = "macho", True

    def open(self, data: bytes):
        return None

    def check_binary(self, binary: Path) -> None:
        assert_text_at_zero(binary)

    def identity_of(self, binary: Path, data: bytes) -> str:
        return sym_module_id_from_uuid(macho_uuid(binary))

    def to_offset(self, ctx, address: int) -> int:
        return address

    def to_vaddr(self, ctx, offset: int) -> int:
        return offset


class _PE:
    name, signs = "pe", False

    def open(self, data: bytes):
        return pe_sections(data)

    def check_binary(self, binary: Path) -> None:
        pass

    def identity_of(self, binary: Path, data: bytes) -> str:
        return pe_codeview_id(data)

    def to_offset(self, sections, rva: int) -> int:
        return pe_rva_to_offset(sections, rva)

    def to_vaddr(self, sections, offset: int) -> int:
        return pe_offset_to_rva(sections, offset)


def binary_format(platform: str):
    if platform.startswith("darwin-") or platform.startswith("mas-"):
        return _MachO()
    if platform.startswith("win32-"):
        return _PE()
    raise SystemExit(f"{platform}: only darwin-*/mas-* (Mach-O) and win32-* (PE) builds are implemented")


def build(version: str, platform: str, patches_root: Path, cache: Path, work: Path, dist: Path) -> Path:
    """Produce dist/electron-v<version>-<platform>.zip with every patch that targets `platform`."""
    targets = [(p, p["targets"][platform]) for p in load_patches(patches_root) if platform in p["targets"]]
    if not targets:
        raise SystemExit(f"no patch targets {platform}; it is a pass-through platform")
    fmt = binary_format(platform)

    zip_name = f"electron-v{version}-{platform}.zip"
    stock_zip = fetch_upstream(version, zip_name, cache)
    symbols_zip = fetch_upstream(version, f"electron-v{version}-{platform}-symbols.zip", cache)

    stock, patched = work / platform / "stock", work / platform / "patched"
    unzip(stock_zip, stock)
    shutil.rmtree(patched, ignore_errors=True)
    shutil.copytree(stock, patched, symlinks=True)

    record = {"version": version, "platform": platform, "patches": []}
    by_binary: dict[str, list[tuple[dict, dict]]] = {}
    for patch, target in targets:
        by_binary.setdefault(target["binary"], []).append((patch, target))

    for rel_binary, group in by_binary.items():
        binary = patched / rel_binary
        fmt.check_binary(binary)
        with open_sym(symbols_zip, binary.name) as sym:
            module_id, funcs = parse_sym(sym)
        data = bytearray(binary.read_bytes())
        ctx = fmt.open(bytes(data))
        identity = fmt.identity_of(binary, bytes(data))
        if identity != module_id:
            raise ValueError(f"{binary.name}: binary identity {identity} does not match symbols MODULE {module_id}")

        def resolve(name: str, funcs=funcs, ctx=ctx) -> tuple[int, int]:
            address, size = resolve_symbol(funcs, name)
            return fmt.to_offset(ctx, address), size

        for patch, target in group:
            sites = apply_sites(data, target["sites"], resolve, to_vaddr=lambda off, ctx=ctx: fmt.to_vaddr(ctx, off))
            for s in sites:
                log(f"{patch['name']}: {s['symbol']} @ {s['offset']:#x} (vaddr {s['vaddr']:#x}): {s['old']} -> {s['new']}")
            record["patches"].append({"name": patch["name"], "binary": rel_binary, "sites": sites})
        binary.write_bytes(bytes(data))

    if fmt.signs:
        codesign_adhoc([patched / rel_binary for rel_binary in by_binary])
    out_zip = dist / zip_name
    rezip(patched, out_zip)
    (dist / f"electron-v{version}-{platform}.patches.json").write_text(json.dumps(record, indent=2) + "\n")
    log(f"wrote {out_zip} ({out_zip.stat().st_size >> 20} MiB)")
    return out_zip


def passthrough(version: str, cache: Path, dist: Path, patches_root: Path) -> list[str]:
    """Copy every upstream platform zip that dist/ does not already hold, verified against upstream.

    Refuses to pass through any platform a loaded patch targets unless that platform's built
    zip is already in dist/: a missing build there would otherwise ship unpatched bytes for
    a platform we claim to patch, silently.
    """
    dist.mkdir(parents=True, exist_ok=True)
    patches = load_patches(patches_root)
    targeted: dict[str, list[str]] = {}
    for p in patches:
        for platform in p["targets"]:
            targeted.setdefault(platform, []).append(p["name"])
    copied = []
    for name in upstream_asset_names(upstream_release(version), version):
        if (dist / name).exists():
            continue
        m = _PLATFORM_ZIP.match(name)
        platform = m.group("platform") if m else None
        if platform in targeted:
            names = ", ".join(targeted[platform])
            raise SystemExit(f"{name}: platform {platform} is patched by {names}; build it first, never pass it through")
        shutil.copy2(fetch_upstream(version, name, cache), dist / name)
        copied.append(name)
        log(f"pass-through {name}")
    return copied


def check_dist(version: str, cache: Path, dist: Path, patches_root: Path) -> None:
    """Assert dist/ is ready to publish for `version`.

    (a) The set of electron-v<version>-*.zip files in dist/ equals the set of platform zip
        names upstream's own SHASUMS256.txt lists for this version — the authoritative
        complete list of what a release must carry, not the (sometimes lagging) API.
    (b) Every pass-through zip in dist/ (i.e. not a platform a loaded patch targets) hashes
        to upstream's value.
    (c) Every *.patches.json in dist/ has its sibling zip.
    """
    shasums = upstream_shasums(version, cache)
    expected = {name for name in shasums if (m := _PLATFORM_ZIP.match(name)) and m.group("v") == version}
    have = {p.name for p in dist.glob(f"electron-v{version}-*.zip")}
    if have != expected:
        missing, extra = sorted(expected - have), sorted(have - expected)
        raise SystemExit(f"dist/ does not match upstream SHASUMS256.txt for v{version}: missing {missing}, extra {extra}")

    targeted = {platform for p in load_patches(patches_root) for platform in p["targets"]}
    for name in sorted(have):
        platform = _PLATFORM_ZIP.match(name).group("platform")
        if platform in targeted:
            continue
        actual = sha256_file(dist / name)
        if actual != shasums[name]:
            raise SystemExit(f"{name}: pass-through sha256 {actual} != upstream {shasums[name]}")

    for rec_path in sorted(dist.glob("*.patches.json")):
        zip_name = rec_path.name.removesuffix(".patches.json") + ".zip"
        if not (dist / zip_name).exists():
            raise SystemExit(f"{rec_path.name}: no sibling zip {zip_name}")
    log(f"check-dist v{version}: {len(have)} zip(s) match upstream, all present, all patches.json paired")


def shasums(dist: Path) -> str:
    return format_shasums({p.name: sha256_file(p) for p in sorted(dist.glob("*.zip"))})


def release_notes(version: str, patched: dict[str, list[str]], passthrough_platforms: list[str], patches: list[dict]) -> str:
    summaries = {p["name"]: p["summary"] for p in patches}
    lines = [
        f"Republishes [Electron v{version}](https://github.com/electron/electron/releases/tag/v{version}) "
        "with game-oriented byte patches. Byte-identical to upstream except the documented patch sites "
        "and the ad-hoc code signature that re-signing them requires.",
        "",
        "## Patched",
    ]
    for platform, names in sorted(patched.items()):
        for name in names:
            lines.append(f"- `{platform}` — {name}: {summaries.get(name, '')} ([details](https://github.com/csarkosh/electron-gamepatch/tree/main/patches/{name}))")
    lines += ["", "## Pass-through (unmodified upstream)", ""]
    lines += [f"- `{p}`" for p in sorted(passthrough_platforms)] or ["- none"]
    lines += [
        "",
        "## Use",
        "",
        "```ini",
        "# .npmrc",
        "electron_mirror=https://github.com/csarkosh/electron-gamepatch/releases/download/",
        "electron_use_remote_checksums=1",
        "```",
        "",
        f"Then `npm install electron@{version}`.",
    ]
    return "\n".join(lines) + "\n"


def notes(version: str, patches_root: Path, dist: Path) -> str:
    patched: dict[str, list[str]] = {}
    for rec_path in sorted(dist.glob("*.patches.json")):
        rec = json.loads(rec_path.read_text())
        patched[rec["platform"]] = [p["name"] for p in rec["patches"]]
    platforms = []
    for p in sorted(dist.glob("*.zip")):
        m = _PLATFORM_ZIP.match(p.name)
        if m and m.group("v") == version:
            platforms.append(m.group("platform"))
    passthrough_platforms = [p for p in platforms if p not in patched]
    return release_notes(version, patched, passthrough_platforms, load_patches(patches_root))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="gamepatch", description=__doc__)
    ap.add_argument("--patches", type=Path, default=Path("patches"))
    ap.add_argument("--cache", type=Path, default=Path("cache"))
    ap.add_argument("--work", type=Path, default=Path("work"))
    ap.add_argument("--dist", type=Path, default=Path("dist"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="patch one platform zip for one version")
    b.add_argument("--version", required=True)
    b.add_argument("--platform", required=True)
    p = sub.add_parser("passthrough", help="add upstream zips for every platform not in dist/")
    p.add_argument("--version", required=True)
    sub.add_parser("shasums", help="print SHASUMS256.txt for dist/*.zip")
    n = sub.add_parser("notes", help="print release notes for dist/")
    n.add_argument("--version", required=True)
    c = sub.add_parser("check-dist", help="assert dist/ is ready to publish for --version")
    c.add_argument("--version", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "build":
        a.dist.mkdir(parents=True, exist_ok=True)
        build(a.version, a.platform, a.patches, a.cache, a.work, a.dist)
    elif a.cmd == "passthrough":
        passthrough(a.version, a.cache, a.dist, a.patches)
    elif a.cmd == "shasums":
        sys.stdout.write(shasums(a.dist))
    elif a.cmd == "notes":
        sys.stdout.write(notes(a.version, a.patches, a.dist))
    elif a.cmd == "check-dist":
        check_dist(a.version, a.cache, a.dist, a.patches)
    return 0


if __name__ == "__main__":
    sys.exit(main())
