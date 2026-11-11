#!/usr/bin/env python3
"""Synthetic M157 upstream graphics compatibility tests (no GPU hardware)."""
import unittest
from unittest import mock

from full_graphics_m157 import (
    PATCHES, GPU_FLAGS, GraphicsCompatError, ensure_build,
    verified_rewrite, apply_graphics_compat_m157
)
from patch_chrome import (
    GL_ALLOWED_ORIG, PatchError, plan_binary_patch,
    M157_P3_ORIGINAL, M157_P3_OFFSET
)


class FullGraphicsCompatTests(unittest.TestCase):
    def test_all_patches_preserve_instruction_span(self):
        self.assertEqual([p[0][:2] for p in PATCHES], ["P5", "P6", "P7"])
        for name, offset, old, new in PATCHES:
            with self.subTest(name=name):
                self.assertGreater(offset, 0)
                self.assertEqual(len(old), len(new))
                self.assertNotEqual(old, new)

    def test_all_graphics_regions_mutated_with_no_overlap(self):
        source = bytearray(b"\xcc" * 350)
        spots = (("P5", 24), ("P6", 100), ("P7", 188))
        for (name, pos), (label, _offset, old, _new) in zip(spots, PATCHES):
            self.assertTrue(label.startswith(name + "_"))
            source[pos:pos + len(old)] = old
        original = bytes(source)
        data = bytearray(original)
        changed = set()
        for (_name, pos), (label, _offset, old, new) in zip(spots, PATCHES):
            verified_rewrite(original, data, label, pos, old, new)
            changed.update(range(pos, pos + len(old)))
        diffs = {i for i, (a, b) in enumerate(zip(original, data)) if a != b}
        self.assertTrue(diffs)
        self.assertTrue(diffs.issubset(changed))
        self.assertEqual(len(data), len(original))
        for (_name, pos), (label, _offset, _old, new) in zip(spots, PATCHES):
            self.assertEqual(data[pos:pos+len(new)], new)

    def test_rejects_non_unique_instruction_pattern(self):
        old = PATCHES[1][2]
        original = old + b"\xcc" * 50 + old
        with self.assertRaisesRegex(GraphicsCompatError, "not unique"):
            verified_rewrite(original, bytearray(original), "P6", 0, old, PATCHES[1][3])

    def test_rejects_modified_stage(self):
        old, new = PATCHES[2][2:4]
        original = b"\x88" * 8 + old
        staged = bytearray(original)
        staged[8] = 0
        with self.assertRaisesRegex(GraphicsCompatError, "already changed"):
            verified_rewrite(original, staged, "P7", 8, old, new)

    def test_rejects_wrong_m157_binary(self):
        with self.assertRaisesRegex(GraphicsCompatError, "exact Chrome"):
            ensure_build(b"\x00" * 5)

    def test_atomicity_when_final_patch_mismatch(self):
        """A failure on P7 must not alter the passed-in already-P1/P2/P3 buffer."""
        original = bytes(b"\xaa" * 500)
        patched = bytearray(original)
        before = bytes(patched)
        with mock.patch("full_graphics_m157.ensure_build"):
            with self.assertRaises(GraphicsCompatError):
                apply_graphics_compat_m157(original, patched)
        self.assertEqual(patched, bytearray(before))

    def test_default_does_not_add_any_graphics_bypass(self):
        original = GL_ALLOWED_ORIG + b"\x20" * 20
        with self.assertRaises(PatchError):
            plan_binary_patch(original)

    def test_all_or_nothing_requires_full_build(self):
        sample = b"\xcc" * 40 + GL_ALLOWED_ORIG
        with self.assertRaises(GraphicsCompatError):
            apply_graphics_compat_m157(sample, sample)

    def test_p4_is_not_included_or_injected(self):
        self.assertFalse(any(name.startswith("P4") for name, *_ in PATCHES))
        self.assertFalse(any("no-sandbox" in s for s in GPU_FLAGS))
        self.assertNotIn("--disable-gpu-sandbox", GPU_FLAGS)
        self.assertIn("--disable-zero-copy", GPU_FLAGS)

    def test_expected_p3_is_user_supplied_m157(self):
        self.assertEqual(M157_P3_OFFSET, 0x1fa5846)
        self.assertIn(bytes.fromhex("c7 45 ac 03 00 00 00"), M157_P3_ORIGINAL)


if __name__ == "__main__":
    unittest.main()
