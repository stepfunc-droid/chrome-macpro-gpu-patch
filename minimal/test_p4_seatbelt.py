#!/usr/bin/env python3
"""Synthetic tests for the opt-in P4 diagnostic. No Chrome binary is needed."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import p4_seatbelt
from adaptive_graphics import verify_patched_regions
from full_graphics_m157 import GraphicsCompatError

ANCHOR = bytes.fromhex(
    "89 c7 31 f6 31 d2 31 c0 e8 11 22 33 44 85 c0 "
    "0f 84 45 00 00 00 48 8b bb 88 00 00 00"
)
POSITIONS = {
    "allowed_gl_jump": 10,
    "display_init_jump": 20,
    "experimental_gl_mode_branch": 30,
    "P5_IOSurfaceFactoryTarget": 120,
    "P6_IOSurfaceValidateTarget_BYPASS": 210,
    "P7_IOSurfaceBackingTarget": 300,
}
VERSION = "157.0.8103.51"


class P4DiagnosticTests(unittest.TestCase):
    def setUp(self):
        data = bytearray(b"\xcc" * 900)
        data[500:500 + len(ANCHOR)] = ANCHOR
        self.original = bytes(data)
        self.digest = hashlib.sha256(self.original).hexdigest()

    def apply(self, original=None, modified=None, positions=None, version=VERSION,
              sha=None):
        original = self.original if original is None else original
        modified = original if modified is None else modified
        positions = POSITIONS if positions is None else positions
        sha = hashlib.sha256(original).hexdigest() if sha is None else sha
        with mock.patch.object(p4_seatbelt, "BUILD_SIZE", len(original)), \
             mock.patch.object(p4_seatbelt, "BUILD_SHA256", sha):
            return p4_seatbelt.make_p4_on_control(
                original, modified, positions, version=version, sha=sha)

    def test_only_p4_guard_changed(self):
        modified, positions = self.apply()
        offset = 500 + 15
        self.assertEqual(positions[p4_seatbelt.P4_NAME], offset)
        self.assertEqual(modified[offset:offset + 6], b"\x90" * 6)
        self.assertEqual(modified[:offset], self.original[:offset])
        self.assertEqual(modified[offset + 6:], self.original[offset + 6:])
        self.assertEqual(len(modified), len(self.original))
        self.assertNotIn(p4_seatbelt.P4_NAME, POSITIONS)

    def test_existing_six_patch_bytes_unchanged(self):
        candidate = bytearray(self.original)
        candidate[12] = 0x90
        candidate[120] = 0x90
        result, _ = self.apply(modified=bytes(candidate))
        self.assertEqual(result[12], 0x90)
        self.assertEqual(result[120], 0x90)

    def test_reject_ambiguous_context(self):
        data = bytearray(self.original)
        data[670:670 + len(ANCHOR)] = ANCHOR
        with self.assertRaisesRegex(GraphicsCompatError, "found 2"):
            self.apply(original=bytes(data))

    def test_readonly_diagnostics_show_strict_and_looser_contexts(self):
        report = p4_seatbelt.diagnose_p4_patterns(self.original, max_examples=2)
        self.assertIn("strict upstream M153+ context: 1 match(es)", report)
        self.assertIn("upstream GpuMain prefix through CALL/TEST: 1 match(es)", report)
        self.assertIn("CALL/TEST/JE-near", report)
        self.assertIn("offset 0x1f4", report)
        self.assertIn("NOT safe patch locations", report)
        self.assertEqual(self.original[515:521], bytes.fromhex("0f 84 45 00 00 00"))

    def test_diagnostic_probe_does_not_return_patchable_offsets(self):
        with self.assertRaisesRegex(ValueError, "max_examples"):
            p4_seatbelt.diagnose_p4_patterns(self.original, max_examples=0)

    def test_reject_absent_context(self):
        with self.assertRaisesRegex(GraphicsCompatError, "found 0"):
            self.apply(original=b"\xcc" * 900)

    def test_reject_unexpected_branch_modification(self):
        candidate = bytearray(self.original)
        candidate[515] = 0x90
        with self.assertRaisesRegex(GraphicsCompatError, "already modified"):
            self.apply(modified=bytes(candidate))

    def test_reject_overlap_with_existing_patch(self):
        pos = dict(POSITIONS)
        pos["P5_IOSurfaceFactoryTarget"] = 510
        with self.assertRaisesRegex(GraphicsCompatError, "overlaps"):
            self.apply(positions=pos)

    def test_reject_incompatible_patch_set(self):
        pos = dict(POSITIONS)
        del pos["P6_IOSurfaceValidateTarget_BYPASS"]
        with self.assertRaisesRegex(GraphicsCompatError, "six-patch"):
            self.apply(positions=pos)

    def test_reject_different_version(self):
        with self.assertRaisesRegex(GraphicsCompatError, "exact Chrome"):
            self.apply(version="158.0.0.1")

    def test_reject_bad_hash_even_with_matching_callers(self):
        with self.assertRaisesRegex(GraphicsCompatError, "exact Chrome"):
            p4_seatbelt.make_p4_on_control(
                self.original, self.original, POSITIONS,
                version=VERSION, sha="0" * 64)

    def test_reject_short_jump_rather_than_guess(self):
        data = bytearray(self.original)
        data[515:521] = b"\x74\x04\x90\x90\x90\x90"
        with self.assertRaisesRegex(GraphicsCompatError, "found 0"):
            self.apply(original=bytes(data))

    def test_verify_seven_patch_regions(self):
        modified, positions = self.apply()
        with tempfile.TemporaryDirectory() as tmp:
            staged = Path(tmp) / "Chrome Framework"
            staged.write_bytes(modified)
            self.assertTrue(verify_patched_regions(staged, modified, positions))
            corrupted = bytearray(modified)
            corrupted[positions[p4_seatbelt.P4_NAME]] = 0x0f
            staged.write_bytes(corrupted)
            with self.assertRaisesRegex(GraphicsCompatError, p4_seatbelt.P4_NAME):
                verify_patched_regions(staged, modified, positions)


if __name__ == "__main__":
    unittest.main()
