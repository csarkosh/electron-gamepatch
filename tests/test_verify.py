import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import verify  # noqa: E402

OBJDUMP = """
Disassembly of section __TEXT,__text:

0000000006266c88 <_ares_llist_node_next>:
 903ca3c: 52800000     \tmov\tw0, #0x0                ; =0
 903ca40: d65f03c0     \tret
"""


class Disasm(unittest.TestCase):
    def test_normalizes_mnemonic_and_operands_only(self):
        self.assertEqual(verify.normalize_disasm(OBJDUMP), ["mov w0, #0x0", "ret"])


class Ranges(unittest.TestCase):
    def test_differing_ranges(self):
        self.assertEqual(verify.differing_ranges(b"aaaaaaaa", b"abaaacca"), [(1, 2), (5, 7)])

    def test_identical(self):
        self.assertEqual(verify.differing_ranges(b"abc", b"abc"), [])

    def test_within(self):
        self.assertTrue(verify.ranges_within([(4, 12)], [(4, 12)]))
        self.assertTrue(verify.ranges_within([(5, 6)], [(4, 12)]))
        self.assertFalse(verify.ranges_within([(3, 6)], [(4, 12)]))
        self.assertFalse(verify.ranges_within([(4, 12), (100, 101)], [(4, 12)]))


class CodeSignature(unittest.TestCase):
    def test_parses_dataoff_and_size(self):
        out = "Load command 30\n      cmd LC_CODE_SIGNATURE\n  cmdsize 16\n  dataoff 189612032\n datasize 1650176\n"
        self.assertEqual(verify.code_signature_range(out), (189612032, 189612032 + 1650176))

    def test_absent(self):
        self.assertIsNone(verify.code_signature_range("cmd LC_SEGMENT_64\n"))


def _mach_header_64(ncmds: int, sizeofcmds: int) -> bytes:
    # magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
    return struct.pack("<8I", 0xFEEDFACF, 0x100000C, 0, 2, ncmds, sizeofcmds, 0, 0)


def _load_command(cmd: int, cmdsize: int, payload: bytes = b"") -> bytes:
    body = struct.pack("<2I", cmd, cmdsize) + payload
    # pad to cmdsize (cmd + cmdsize fields are 8 bytes; the rest is padding for this synthetic test)
    return body.ljust(cmdsize, b"\x00")


class LoadCommandRanges(unittest.TestCase):
    def test_returns_only_matching_cmd_ranges(self):
        seg = _load_command(0x19, 56)  # LC_SEGMENT_64-like
        sig = _load_command(0x1D, 16)  # LC_CODE_SIGNATURE-like
        header = _mach_header_64(2, len(seg) + len(sig)) + seg + sig
        seg_start = 32
        sig_start = seg_start + len(seg)
        self.assertEqual(verify.load_command_ranges(header, cmd=0x1D), [(sig_start, sig_start + len(sig))])
        self.assertEqual(verify.load_command_ranges(header, cmd=0x19), [(seg_start, seg_start + len(seg))])

    def test_wrong_magic_returns_empty(self):
        header = struct.pack("<8I", 0xDEADBEEF, 0, 0, 0, 0, 0, 0, 0)
        self.assertEqual(verify.load_command_ranges(header, cmd=0x1D), [])


if __name__ == "__main__":
    unittest.main()
