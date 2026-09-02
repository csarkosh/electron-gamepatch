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


def _objdump(insn: str) -> str:
    """One disassembled instruction wrapped in a minimal objdump listing, matching verify._INSN."""
    return f" 903ca3c: 52800000     \t{insn}\n"


class Disasm(unittest.TestCase):
    def test_normalizes_mnemonic_and_operands_only(self):
        self.assertEqual(verify.normalize_disasm(OBJDUMP), ["mov w0, #0x0", "ret"])

    def test_decimal_and_hex_zero_immediates_normalize_identically(self):
        self.assertEqual(verify.normalize_disasm(_objdump("mov\tw0, #0")), ["mov w0, #0x0"])
        self.assertEqual(verify.normalize_disasm(_objdump("mov\tw0, #0x0")), ["mov w0, #0x0"])

    def test_decimal_and_hex_nonzero_immediates_normalize_identically(self):
        self.assertEqual(verify.normalize_disasm(_objdump("mov\tw1, #0x8                ; =8")), ["mov w1, #0x8"])
        self.assertEqual(verify.normalize_disasm(_objdump("mov\tw1, #8")), ["mov w1, #0x8"])

    def test_multiple_immediates_on_one_line(self):
        self.assertEqual(verify.normalize_disasm(_objdump("movk\tw9, #0x13, lsl #16")), ["movk w9, #0x13, lsl #0x10"])

    def test_negative_immediate_stays_negative(self):
        self.assertEqual(verify.normalize_disasm(_objdump("sub\tsp, sp, #-16")), ["sub sp, sp, #-0x10"])

    def test_register_only_lines_are_unchanged(self):
        self.assertEqual(verify.normalize_disasm(_objdump("ret")), ["ret"])
        self.assertEqual(verify.normalize_disasm(_objdump("mov\tx0, x1")), ["mov x0, x1"])


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


class SignatureReachesEof(unittest.TestCase):
    def test_true_when_signature_end_is_file_end(self):
        self.assertTrue(verify.signature_reaches_eof((1000, 1650), 1650))

    def test_false_when_bytes_hide_after_signature(self):
        self.assertFalse(verify.signature_reaches_eof((1000, 1650), 1700))

    def test_false_when_no_signature_present(self):
        self.assertFalse(verify.signature_reaches_eof(None, 1650))


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


def _segment64_command(segname: bytes, vmsize: int, filesize: int) -> bytes:
    """A minimal segment_command_64 (no sections): cmd(4) cmdsize(4) segname(16) vmaddr(8)
    vmsize(8) fileoff(8) filesize(8) maxprot(4) initprot(4) nsects(4) flags(4) = 72 bytes."""
    return struct.pack(
        "<2I16sQQQQ4I",
        0x19, 72, segname.ljust(16, b"\x00"),
        0, vmsize, 0, filesize,
        7, 7, 0, 0,
    )


class CodesignOwnedRanges(unittest.TestCase):
    def test_linkedit_vmsize_filesize_and_code_signature_only(self):
        text_seg = _segment64_command(b"__TEXT", vmsize=0x1000, filesize=0x1000)
        linkedit_seg = _segment64_command(b"__LINKEDIT", vmsize=0x5000, filesize=0x4000)
        sig = _load_command(0x1D, 16)
        header = _mach_header_64(3, len(text_seg) + len(linkedit_seg) + len(sig)) + text_seg + linkedit_seg + sig

        text_start = 32
        linkedit_start = text_start + len(text_seg)
        sig_start = linkedit_start + len(linkedit_seg)

        expected = [
            (sig_start, sig_start + len(sig)),
            (linkedit_start + 32, linkedit_start + 40),  # vmsize
            (linkedit_start + 48, linkedit_start + 56),  # filesize
        ]
        self.assertEqual(verify.codesign_owned_ranges(header), expected)

        # __TEXT's window must not appear anywhere in the result.
        for start, end in expected:
            self.assertFalse(text_start <= start < text_start + len(text_seg))

    def test_wrong_magic_returns_empty(self):
        header = struct.pack("<8I", 0xDEADBEEF, 0, 0, 0, 0, 0, 0, 0)
        self.assertEqual(verify.codesign_owned_ranges(header), [])


if __name__ == "__main__":
    unittest.main()
