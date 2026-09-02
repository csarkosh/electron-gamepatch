import json
import sys
import tempfile
import unittest
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


class Shasums(unittest.TestCase):
    def test_format_sorted_with_binary_marker(self):
        text = gamepatch.format_shasums({"b.zip": "22", "a.zip": "11"})
        self.assertEqual(text, "11 *a.zip\n22 *b.zip\n")

    def test_parse_roundtrip(self):
        self.assertEqual(gamepatch.parse_shasums("11 *a.zip\n22 *b.zip\n\n"), {"a.zip": "11", "b.zip": "22"})


if __name__ == "__main__":
    unittest.main()
