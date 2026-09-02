import hashlib
import json
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import gamepatch  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


class ParseSym(unittest.TestCase):
    def setUp(self):
        with open(FIXTURES / "framework.sym") as f:
            self.module_id, self.funcs = gamepatch.parse_sym(f)

    def test_module_id(self):
        self.assertEqual(self.module_id, "4C4C448B55553144A1795775D5EF8BF60")

    def test_func_address_and_size(self):
        self.assertEqual(
            self.funcs["PointerLockController::HandleUserPressedEscape()"], [(0x903CA3C, 0x44)]
        )

    def test_multiple_flag_is_parsed(self):
        self.assertEqual(self.funcs["PointerLockController::HandleUserHeldEscape()"], [(0x903CA80, 4)])

    def test_duplicate_names_are_kept(self):
        self.assertEqual(len(self.funcs["PointerLockController::~PointerLockController()"]), 2)

    def test_missing_module_line_raises(self):
        with self.assertRaises(ValueError):
            gamepatch.parse_sym(["FUNC 1 2 0 f()"])


class ParseWindowsSym(unittest.TestCase):
    def test_module_id_and_rva(self):
        with open(FIXTURES / "electron.exe.sym") as f:
            module_id, funcs = gamepatch.parse_sym(f)
        self.assertEqual(module_id, "E576D66B49E136884C4C44205044422E1")
        self.assertEqual(funcs["PointerLockController::HandleUserPressedEscape()"], [(0x7C53420, 0x6E)])


class ResolveSymbol(unittest.TestCase):
    def test_unique(self):
        self.assertEqual(gamepatch.resolve_symbol({"f()": [(16, 4)]}, "f()"), (16, 4))

    def test_missing_raises(self):
        with self.assertRaises(LookupError):
            gamepatch.resolve_symbol({}, "f()")

    def test_ambiguous_raises(self):
        with self.assertRaises(LookupError):
            gamepatch.resolve_symbol({"f()": [(16, 4), (32, 4)]}, "f()")


SITE = {"symbol": "f()", "offset": 0, "expect": "f44fbea9", "write": "00008052", "asm": ["mov w0, #0x0"]}


class ApplySites(unittest.TestCase):
    def resolver(self, name):
        return {"f()": (4, 8)}[name]

    def test_patches_in_place_and_records(self):
        data = bytearray(b"\x00" * 4 + bytes.fromhex("f44fbea9fd7b01a9") + b"\x00" * 4)
        records = gamepatch.apply_sites(data, [SITE], self.resolver)
        self.assertEqual(data[4:8].hex(), "00008052")
        self.assertEqual(data[8:12].hex(), "fd7b01a9")
        self.assertEqual(
            records,
            [{"symbol": "f()", "offset": 4, "vaddr": 4, "length": 4, "old": "f44fbea9", "new": "00008052", "asm": ["mov w0, #0x0"]}],
        )

    def test_offset_within_function(self):
        data = bytearray(b"\x00" * 4 + bytes.fromhex("f44fbea9fd7b01a9") + b"\x00" * 4)
        site = dict(SITE, offset=4, expect="fd7b01a9", write="c0035fd6")
        gamepatch.apply_sites(data, [site], self.resolver)
        self.assertEqual(data[8:12].hex(), "c0035fd6")

    def test_unexpected_bytes_raise_and_leave_data_untouched(self):
        data = bytearray(b"\xaa" * 16)
        with self.assertRaises(ValueError) as cm:
            gamepatch.apply_sites(data, [SITE], self.resolver)
        self.assertIn("found aaaaaaaa", str(cm.exception))
        self.assertEqual(data, bytearray(b"\xaa" * 16))

    def test_site_past_function_end_raises(self):
        data = bytearray(b"\x00" * 32)
        with self.assertRaises(ValueError):
            gamepatch.apply_sites(data, [dict(SITE, offset=6)], self.resolver)

    def test_length_mismatch_raises(self):
        data = bytearray(b"\x00" * 32)
        with self.assertRaises(ValueError):
            gamepatch.apply_sites(data, [dict(SITE, write="00")], self.resolver)


class ApplySitesVaddr(unittest.TestCase):
    def test_vaddr_is_translated_and_offset_is_file_space(self):
        data = bytearray(b"\0" * 0x200 + bytes.fromhex("565753") + b"\x90" * 61)
        # Symbols say the function is at RVA 0x1000, size 0x40; the file holds it at 0x200.
        sections = [{"name": ".text", "rva": 0x1000, "vsize": 0x40, "rawoff": 0x200, "rawsize": 0x40}]
        site = {"symbol": "f()", "offset": 0, "expect": "565753", "write": "31c0c3", "asm": ["xor eax, eax", "ret"]}
        resolve = lambda name: (gamepatch.pe_rva_to_offset(sections, 0x1000), 0x40)
        records = gamepatch.apply_sites(data, [site], resolve, to_vaddr=lambda off: gamepatch.pe_offset_to_rva(sections, off))
        self.assertEqual(records[0]["offset"], 0x200)
        self.assertEqual(records[0]["vaddr"], 0x1000)
        self.assertEqual(data[0x200:0x203], bytes.fromhex("31c0c3"))


class Formats(unittest.TestCase):
    def test_platform_prefix_selects_format(self):
        self.assertEqual(gamepatch.binary_format("darwin-arm64").name, "macho")
        self.assertEqual(gamepatch.binary_format("darwin-x64").name, "macho")
        self.assertEqual(gamepatch.binary_format("win32-x64").name, "pe")
        with self.assertRaises(SystemExit):
            gamepatch.binary_format("linux-x64")

    def test_pe_format_resolves_through_sections_and_identity(self):
        pe = make_pe([(".text", 0x1000, b"\0" * 64 + bytes.fromhex("565753") + b"\x90" * 61)])
        fmt = gamepatch.binary_format("win32-x64")
        ctx = fmt.open(pe)
        self.assertEqual(fmt.identity_of(Path("unused"), pe), "E576D66B49E136884C4C44205044422E1")
        self.assertEqual(fmt.to_offset(ctx, 0x1040), 0x240)
        self.assertEqual(fmt.to_vaddr(ctx, 0x240), 0x1040)
        self.assertFalse(fmt.signs)


class LoadPatch(unittest.TestCase):
    def write(self, obj):
        d = Path(tempfile.mkdtemp())
        (d / "patch.json").write_text(json.dumps(obj))
        return d / "patch.json"

    def test_real_patch_loads(self):
        p = gamepatch.load_patch(Path(__file__).parents[1] / "patches/pointerlock-noeject/patch.json")
        self.assertEqual(p["name"], "pointerlock-noeject")
        self.assertEqual(sorted(p["targets"]), ["darwin-arm64", "win32-x64"])

    def test_rejects_odd_hex(self):
        bad = {"name": "x", "summary": "s", "targets": {"darwin-arm64": {"binary": "b", "sites": [dict(SITE, expect="abc")]}}}
        with self.assertRaises(ValueError):
            gamepatch.load_patch(self.write(bad))

    def test_rejects_missing_asm(self):
        site = {k: v for k, v in SITE.items() if k != "asm"}
        bad = {"name": "x", "summary": "s", "targets": {"darwin-arm64": {"binary": "b", "sites": [site]}}}
        with self.assertRaises(ValueError):
            gamepatch.load_patch(self.write(bad))

    def test_upstream_source_optional_but_must_be_nonempty_string_if_present(self):
        base = {"name": "x", "summary": "s", "targets": {"darwin-arm64": {"binary": "b", "sites": [SITE]}}}
        # absent: fine
        gamepatch.load_patch(self.write(base))
        # present, non-empty string: fine
        gamepatch.load_patch(self.write(dict(base, upstream_source="chrome/foo.cc")))
        # present, empty string: rejected
        with self.assertRaises(ValueError):
            gamepatch.load_patch(self.write(dict(base, upstream_source="")))
        # present, wrong type: rejected
        with self.assertRaises(ValueError):
            gamepatch.load_patch(self.write(dict(base, upstream_source=123)))


class Shasums(unittest.TestCase):
    def test_format_sorted_with_binary_marker(self):
        text = gamepatch.format_shasums({"b.zip": "22", "a.zip": "11"})
        self.assertEqual(text, "11 *a.zip\n22 *b.zip\n")

    def test_parse_roundtrip(self):
        self.assertEqual(gamepatch.parse_shasums("11 *a.zip\n22 *b.zip\n\n"), {"a.zip": "11", "b.zip": "22"})


class UpstreamAssets(unittest.TestCase):
    RELEASE = {"assets": [
        {"name": "electron-v44.1.1-darwin-arm64.zip"},
        {"name": "electron-v44.1.1-darwin-arm64-symbols.zip"},
        {"name": "electron-v44.1.1-win32-x64.zip"},
        {"name": "chromedriver-v44.1.1-linux-x64.zip"},
        {"name": "electron-v44.1.1-linux-armv7l.zip"},
        {"name": "SHASUMS256.txt"},
    ]}

    def test_only_electron_platform_zips(self):
        self.assertEqual(
            gamepatch.upstream_asset_names(self.RELEASE, "44.1.1"),
            ["electron-v44.1.1-darwin-arm64.zip", "electron-v44.1.1-linux-armv7l.zip", "electron-v44.1.1-win32-x64.zip"],
        )


class MachOHelpers(unittest.TestCase):
    def test_sym_module_id_from_uuid(self):
        self.assertEqual(
            gamepatch.sym_module_id_from_uuid("4C4C448B-5555-3144-A179-5775D5EF8BF6"),
            "4C4C448B55553144A1795775D5EF8BF60",
        )

    def test_text_segment_at_zero(self):
        out = "Load command 1\n      cmd LC_SEGMENT_64\n  segname __TEXT\n   vmaddr 0x0000000000000000\n   vmsize 0x0b4d4000\n  fileoff 0\n filesize 189612032\n"
        self.assertTrue(gamepatch.text_segment_is_at_zero(out))

    def test_text_segment_not_at_zero(self):
        out = "  segname __TEXT\n   vmaddr 0x0000000100000000\n   vmsize 0x1000\n  fileoff 0\n"
        self.assertFalse(gamepatch.text_segment_is_at_zero(out))


PATCHES_ROOT = Path(__file__).parents[1] / "patches"  # real patches/: pointerlock-noeject targets darwin-arm64 and win32-x64


class Passthrough(unittest.TestCase):
    RELEASE = {"assets": [
        {"name": "electron-v44.1.1-darwin-arm64.zip"},
        {"name": "electron-v44.1.1-linux-x64.zip"},
    ]}

    def setUp(self):
        self.dist = Path(tempfile.mkdtemp())
        self.cache = Path(tempfile.mkdtemp())
        orig_release, orig_fetch = gamepatch.upstream_release, gamepatch.fetch_upstream
        gamepatch.upstream_release = lambda version: self.RELEASE
        self.addCleanup(setattr, gamepatch, "upstream_release", orig_release)
        self.addCleanup(setattr, gamepatch, "fetch_upstream", orig_fetch)

    def test_raises_for_missing_targeted_platform_zip(self):
        def unreachable(version, filename, cache):
            raise AssertionError(f"fetch_upstream must not be called for {filename}: darwin-arm64 is targeted and unbuilt")
        gamepatch.fetch_upstream = unreachable
        with self.assertRaises(SystemExit) as cm:
            gamepatch.passthrough("44.1.1", self.cache, self.dist, PATCHES_ROOT)
        self.assertIn("darwin-arm64", str(cm.exception))
        self.assertIn("pointerlock-noeject", str(cm.exception))
        self.assertIn("build it first", str(cm.exception))

    def test_passes_through_unpatched_platform_when_patched_zip_present(self):
        (self.dist / "electron-v44.1.1-darwin-arm64.zip").write_bytes(b"already-built-and-patched")
        (self.dist / "electron-v44.1.1-win32-x64.zip").write_bytes(b"already-built-and-patched")

        def fake_fetch(version, filename, cache):
            p = self.cache / filename
            p.write_bytes(b"upstream-bytes")
            return p
        gamepatch.fetch_upstream = fake_fetch
        copied = gamepatch.passthrough("44.1.1", self.cache, self.dist, PATCHES_ROOT)
        self.assertEqual(copied, ["electron-v44.1.1-linux-x64.zip"])
        self.assertTrue((self.dist / "electron-v44.1.1-linux-x64.zip").exists())


class CheckDist(unittest.TestCase):
    def setUp(self):
        self.dist = Path(tempfile.mkdtemp())
        self.cache = Path(tempfile.mkdtemp())
        orig = gamepatch.upstream_shasums
        self.addCleanup(setattr, gamepatch, "upstream_shasums", orig)

    def stub_shasums(self, entries):
        gamepatch.upstream_shasums = lambda version, cache: entries

    def test_missing_zip_from_upstream_set_raises(self):
        self.stub_shasums({
            "electron-v44.1.1-darwin-arm64.zip": "aaa",
            "electron-v44.1.1-linux-x64.zip": "bbb",
        })
        (self.dist / "electron-v44.1.1-darwin-arm64.zip").write_bytes(b"patched-bytes")
        with self.assertRaises(SystemExit) as cm:
            gamepatch.check_dist("44.1.1", self.cache, self.dist, PATCHES_ROOT)
        self.assertIn("electron-v44.1.1-linux-x64.zip", str(cm.exception))

    def test_passthrough_hash_mismatch_raises(self):
        data = b"fake-zip-bytes"
        real_sha = hashlib.sha256(data).hexdigest()
        self.stub_shasums({
            "electron-v44.1.1-darwin-arm64.zip": "unused-patched-platform-sha",
            "electron-v44.1.1-linux-x64.zip": real_sha,
        })
        (self.dist / "electron-v44.1.1-darwin-arm64.zip").write_bytes(b"patched-bytes")
        (self.dist / "electron-v44.1.1-linux-x64.zip").write_bytes(b"corrupted, not upstream's bytes")
        with self.assertRaises(SystemExit) as cm:
            gamepatch.check_dist("44.1.1", self.cache, self.dist, PATCHES_ROOT)
        self.assertIn("electron-v44.1.1-linux-x64.zip", str(cm.exception))

    def test_patches_json_without_sibling_zip_raises(self):
        data = b"fake-zip-bytes"
        real_sha = hashlib.sha256(data).hexdigest()
        self.stub_shasums({
            "electron-v44.1.1-darwin-arm64.zip": "unused-patched-platform-sha",
            "electron-v44.1.1-linux-x64.zip": real_sha,
        })
        (self.dist / "electron-v44.1.1-darwin-arm64.zip").write_bytes(b"patched-bytes")
        (self.dist / "electron-v44.1.1-linux-x64.zip").write_bytes(data)
        (self.dist / "electron-v9.0.0-linux-x64.patches.json").write_text("{}")
        with self.assertRaises(SystemExit) as cm:
            gamepatch.check_dist("44.1.1", self.cache, self.dist, PATCHES_ROOT)
        self.assertIn("electron-v9.0.0-linux-x64.zip", str(cm.exception))

    def test_passes_when_set_matches_hashes_match_and_siblings_present(self):
        data = b"fake-zip-bytes"
        real_sha = hashlib.sha256(data).hexdigest()
        self.stub_shasums({
            "electron-v44.1.1-darwin-arm64.zip": "unused-patched-platform-sha",
            "electron-v44.1.1-linux-x64.zip": real_sha,
        })
        (self.dist / "electron-v44.1.1-darwin-arm64.zip").write_bytes(b"patched-bytes")
        (self.dist / "electron-v44.1.1-linux-x64.zip").write_bytes(data)
        (self.dist / "electron-v44.1.1-darwin-arm64.patches.json").write_text("{}")
        gamepatch.check_dist("44.1.1", self.cache, self.dist, PATCHES_ROOT)  # must not raise


class OpenSym(unittest.TestCase):
    def test_closes_zip_and_stream_on_exit(self):
        zip_path = Path(tempfile.mkdtemp()) / "electron-symbols.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("breakpad_symbols/Electron Framework/ID/Electron Framework.sym", "MODULE mac arm64 ID Electron Framework\n")
        with gamepatch.open_sym(zip_path, "Electron Framework") as sym:
            self.assertIn("MODULE", sym.readline())
        # The zip file backing the stream must be closed after the context exits.
        self.assertTrue(sym.closed)


class ReleaseNotes(unittest.TestCase):
    def test_lists_patched_and_passthrough(self):
        patches = [{"name": "pointerlock-noeject", "summary": "Esc never ejects pointer lock."}]
        notes = gamepatch.release_notes("44.1.1", {"darwin-arm64": ["pointerlock-noeject"]}, ["win32-x64"], patches)
        self.assertIn("Electron v44.1.1", notes)
        self.assertIn("https://github.com/electron/electron/releases/tag/v44.1.1", notes)
        self.assertIn("`darwin-arm64` — pointerlock-noeject", notes)
        self.assertIn("`win32-x64`", notes)
        self.assertIn("electron_use_remote_checksums=1", notes)

    def test_notes_cli_filters_passthrough_by_version(self):
        dist = Path(tempfile.mkdtemp())
        (dist / "electron-v44.1.1-darwin-arm64.zip").write_bytes(b"")
        (dist / "electron-v44.1.1-win32-x64.zip").write_bytes(b"")
        (dist / "electron-v9.0.0-linux-x64.zip").write_bytes(b"")
        (dist / "electron-v44.1.1-darwin-arm64.patches.json").write_text(json.dumps({
            "version": "44.1.1",
            "platform": "darwin-arm64",
            "patches": [{"name": "pointerlock-noeject", "binary": "x", "sites": []}],
        }))
        patches_root = Path(__file__).parents[1] / "patches"
        notes = gamepatch.notes("44.1.1", patches_root, dist)
        self.assertIn("`win32-x64`", notes)
        self.assertNotIn("9.0.0", notes)
        self.assertNotIn("linux-x64", notes)
        # The pass-through section must list exactly `win32-x64` and nothing else — this is
        # the precise, sound version of "not corrupted by a stale zip's mis-sliced platform
        # name": a plain assertNotIn("in32", notes) is unsound here because the correct,
        # uncorrupted string "`win32-x64`" itself contains "in32" as a substring.
        section = notes.split("## Pass-through (unmodified upstream)\n\n", 1)[1].split("\n\n## Use", 1)[0]
        self.assertEqual(section, "- `win32-x64`")


def make_pe(sections, guid=b"\x6b\xd6\x76\xe5\xe1\x49\x88\x36\x4c\x4c\x44\x20\x50\x44\x42\x2e", age=1, image_base=0x140000000):
    """A minimal PE32+ image: DOS stub, COFF header, optional header with a debug
    directory, section table, then each section's raw bytes at its rawoff.
    `sections` = [(name, rva, raw_bytes)]. The RSDS debug record lives inside the
    first section's raw data at its start (raw bytes must leave room: 24 bytes)."""
    n = len(sections)
    e_lfanew = 0x80
    opt_size = 240
    sec_table = e_lfanew + 4 + 20 + opt_size
    headers_end = sec_table + 40 * n
    # Lay sections out on 0x200 boundaries after the headers.
    layout, rawoff = [], (headers_end + 0x1FF) & ~0x1FF
    for name, rva, raw in sections:
        rawsize = (len(raw) + 0x1FF) & ~0x1FF
        layout.append((name, rva, raw, rawoff, rawsize))
        rawoff += rawsize
    total = rawoff
    buf = bytearray(total)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew : e_lfanew + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", buf, e_lfanew + 4, 0x8664, n, 0, 0, 0, opt_size, 0x22)
    opt = e_lfanew + 24
    struct.pack_into("<H", buf, opt, 0x20B)  # PE32+
    struct.pack_into("<Q", buf, opt + 24, image_base)
    struct.pack_into("<I", buf, opt + 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", buf, opt + 36, 0x200)  # FileAlignment
    struct.pack_into("<I", buf, opt + 108, 16)  # NumberOfRvaAndSizes
    # Debug directory (index 6) points at one IMAGE_DEBUG_DIRECTORY entry we place
    # right after the RSDS record in section 0: record at +0, entry at +32.
    first_name, first_rva, first_raw, first_rawoff, _ = layout[0]
    debug_dir_rva = first_rva + 32
    struct.pack_into("<II", buf, opt + 112 + 6 * 8, debug_dir_rva, 28)
    for i, (name, rva, raw, off, rawsize) in enumerate(layout):
        o = sec_table + 40 * i
        buf[o : o + 8] = name.encode().ljust(8, b"\0")
        struct.pack_into("<IIII", buf, o + 8, len(raw), rva, rawsize, off)
        buf[off : off + len(raw)] = raw
    # RSDS record: "RSDS" + GUID(16) + age(4) + "x.pdb\0"
    rsds = b"RSDS" + guid + struct.pack("<I", age) + b"electron.exe.pdb\0"
    buf[first_rawoff : first_rawoff + len(rsds)] = rsds
    # IMAGE_DEBUG_DIRECTORY: Characteristics, TimeDateStamp, Major, Minor, Type=2 (CODEVIEW), SizeOfData, AddressOfRawData, PointerToRawData
    struct.pack_into("<IIHHIIII", buf, first_rawoff + 32, 0, 0, 0, 0, 2, len(rsds), first_rva, first_rawoff)
    return bytes(buf)


class PEHelpers(unittest.TestCase):
    def setUp(self):
        self.pe = make_pe([
            (".text", 0x1000, b"\0" * 64 + bytes.fromhex("565753") + b"\x90" * 61),
            (".rsrc", 0x3000, b"R" * 100),
        ])
        self.sections = gamepatch.pe_sections(self.pe)

    def test_sections_parse_in_order(self):
        self.assertEqual([s["name"] for s in self.sections], [".text", ".rsrc"])
        self.assertEqual(self.sections[0]["rva"], 0x1000)
        self.assertEqual(self.sections[0]["rawoff"], 0x200)
        self.assertEqual(self.sections[1]["rva"], 0x3000)
        self.assertEqual(self.sections[1]["rawoff"], 0x400)

    def test_image_base(self):
        self.assertEqual(gamepatch.pe_image_base(self.pe), 0x140000000)

    def test_rva_to_offset_inside_each_section(self):
        self.assertEqual(gamepatch.pe_rva_to_offset(self.sections, 0x1040), 0x240)
        self.assertEqual(gamepatch.pe_rva_to_offset(self.sections, 0x3005), 0x405)
        self.assertEqual(self.pe[0x240:0x243], bytes.fromhex("565753"))

    def test_rva_in_a_gap_raises(self):
        with self.assertRaises(ValueError):
            gamepatch.pe_rva_to_offset(self.sections, 0x2000)
        with self.assertRaises(ValueError):
            gamepatch.pe_rva_to_offset(self.sections, 0x0)

    def test_offset_to_rva_roundtrips(self):
        self.assertEqual(gamepatch.pe_offset_to_rva(self.sections, 0x240), 0x1040)
        with self.assertRaises(ValueError):
            gamepatch.pe_offset_to_rva(self.sections, 0x10)

    def test_codeview_id_matches_breakpad_format(self):
        # GUID {e576d66b-49e1-3688-4c4c-44205044422e} age 1 → Breakpad "E576D66B49E136884C4C44205044422E1"
        self.assertEqual(gamepatch.pe_codeview_id(self.pe), "E576D66B49E136884C4C44205044422E1")

    def test_not_pe_raises(self):
        with self.assertRaises(ValueError):
            gamepatch.pe_sections(b"\xcf\xfa\xed\xfe" + b"\0" * 64)

    def test_truncated_before_coff_header_raises_value_error(self):
        # Valid MZ + e_lfanew + "PE\0\0", but nothing after: the COFF header
        # itself is cut off, so struct.unpack_from would raise struct.error.
        e_lfanew = 0x80
        with self.assertRaises(ValueError):
            gamepatch.pe_sections(self.pe[: e_lfanew + 4])

    def test_truncated_before_section_table_raises_value_error(self):
        # Valid COFF + optional header, but the section table itself is cut off.
        e_lfanew, opt_size = 0x80, 240
        sec_table = e_lfanew + 4 + 20 + opt_size
        with self.assertRaises(ValueError):
            gamepatch.pe_sections(self.pe[:sec_table])


if __name__ == "__main__":
    unittest.main()
