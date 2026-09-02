import hashlib
import json
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
            [{"symbol": "f()", "offset": 4, "length": 4, "old": "f44fbea9", "new": "00008052", "asm": ["mov w0, #0x0"]}],
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


class LoadPatch(unittest.TestCase):
    def write(self, obj):
        d = Path(tempfile.mkdtemp())
        (d / "patch.json").write_text(json.dumps(obj))
        return d / "patch.json"

    def test_real_patch_loads(self):
        p = gamepatch.load_patch(Path(__file__).parents[1] / "patches/pointerlock-noeject/patch.json")
        self.assertEqual(p["name"], "pointerlock-noeject")
        self.assertIn("darwin-arm64", p["targets"])

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


PATCHES_ROOT = Path(__file__).parents[1] / "patches"  # real patches/: pointerlock-noeject targets darwin-arm64 only


class Passthrough(unittest.TestCase):
    RELEASE = {"assets": [
        {"name": "electron-v44.1.1-darwin-arm64.zip"},
        {"name": "electron-v44.1.1-win32-x64.zip"},
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

        def fake_fetch(version, filename, cache):
            p = self.cache / filename
            p.write_bytes(b"upstream-bytes")
            return p
        gamepatch.fetch_upstream = fake_fetch
        copied = gamepatch.passthrough("44.1.1", self.cache, self.dist, PATCHES_ROOT)
        self.assertEqual(copied, ["electron-v44.1.1-win32-x64.zip"])
        self.assertTrue((self.dist / "electron-v44.1.1-win32-x64.zip").exists())


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
            "electron-v44.1.1-win32-x64.zip": "bbb",
        })
        (self.dist / "electron-v44.1.1-darwin-arm64.zip").write_bytes(b"patched-bytes")
        with self.assertRaises(SystemExit) as cm:
            gamepatch.check_dist("44.1.1", self.cache, self.dist, PATCHES_ROOT)
        self.assertIn("electron-v44.1.1-win32-x64.zip", str(cm.exception))

    def test_passthrough_hash_mismatch_raises(self):
        data = b"fake-zip-bytes"
        real_sha = hashlib.sha256(data).hexdigest()
        self.stub_shasums({
            "electron-v44.1.1-darwin-arm64.zip": "unused-patched-platform-sha",
            "electron-v44.1.1-win32-x64.zip": real_sha,
        })
        (self.dist / "electron-v44.1.1-darwin-arm64.zip").write_bytes(b"patched-bytes")
        (self.dist / "electron-v44.1.1-win32-x64.zip").write_bytes(b"corrupted, not upstream's bytes")
        with self.assertRaises(SystemExit) as cm:
            gamepatch.check_dist("44.1.1", self.cache, self.dist, PATCHES_ROOT)
        self.assertIn("electron-v44.1.1-win32-x64.zip", str(cm.exception))

    def test_patches_json_without_sibling_zip_raises(self):
        data = b"fake-zip-bytes"
        real_sha = hashlib.sha256(data).hexdigest()
        self.stub_shasums({
            "electron-v44.1.1-darwin-arm64.zip": "unused-patched-platform-sha",
            "electron-v44.1.1-win32-x64.zip": real_sha,
        })
        (self.dist / "electron-v44.1.1-darwin-arm64.zip").write_bytes(b"patched-bytes")
        (self.dist / "electron-v44.1.1-win32-x64.zip").write_bytes(data)
        (self.dist / "electron-v9.0.0-linux-x64.patches.json").write_text("{}")
        with self.assertRaises(SystemExit) as cm:
            gamepatch.check_dist("44.1.1", self.cache, self.dist, PATCHES_ROOT)
        self.assertIn("electron-v9.0.0-linux-x64.zip", str(cm.exception))

    def test_passes_when_set_matches_hashes_match_and_siblings_present(self):
        data = b"fake-zip-bytes"
        real_sha = hashlib.sha256(data).hexdigest()
        self.stub_shasums({
            "electron-v44.1.1-darwin-arm64.zip": "unused-patched-platform-sha",
            "electron-v44.1.1-win32-x64.zip": real_sha,
        })
        (self.dist / "electron-v44.1.1-darwin-arm64.zip").write_bytes(b"patched-bytes")
        (self.dist / "electron-v44.1.1-win32-x64.zip").write_bytes(data)
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


if __name__ == "__main__":
    unittest.main()
