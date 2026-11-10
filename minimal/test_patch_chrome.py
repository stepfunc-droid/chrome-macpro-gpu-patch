#!/usr/bin/env python3
"""Synthetic byte-pattern tests; does not test actual Chrome or GPU hardware."""
import struct
import unittest

from patch_chrome import GL_ALLOWED_ORIG, PatchError, plan_binary_patch


def fixture(displacement=0x606):
    display = (b"\x84\xc0\x0f\x85" + struct.pack("<i", displacement)
               + b"\x48\xb8\x09\x00\x00\x00\x03\x00")
    return b"\x11" * 32 + GL_ALLOWED_ORIG + b"\x22" * 32 + display + b"\x33" * 32


class BinaryPatchTests(unittest.TestCase):
    def test_exact_two_changes_and_same_size(self):
        original = fixture()
        modified, offsets = plan_binary_patch(original)
        self.assertEqual(len(original), len(modified))
        differences = [i for i, (a, b) in enumerate(zip(original, modified)) if a != b]
        self.assertTrue(differences)
        self.assertEqual(modified[offsets["allowed_gl_jump"]:offsets["allowed_gl_jump"]+2],
                         b"\x90\x90")
        self.assertEqual(modified[offsets["display_init_jump"]:offsets["display_init_jump"]+6],
                         b"\xe9" + struct.pack("<i", 0x607) + b"\x90")
        self.assertEqual(original, fixture(), "source bytes must never be changed in place")

    def test_negative_relative_jump_target_preserved(self):
        modified, offsets = plan_binary_patch(fixture(-32))
        p = offsets["display_init_jump"]
        self.assertEqual(modified[p:p + 6], b"\xe9" + struct.pack("<i", -31) + b"\x90")

    def test_missing_patterns_fail_closed(self):
        with self.assertRaises(PatchError):
            plan_binary_patch(b"\x00" * 100)
        with self.assertRaises(PatchError):
            plan_binary_patch(GL_ALLOWED_ORIG + b"\x00" * 100)

    def test_duplicate_allowed_gl_pattern_fails(self):
        with self.assertRaises(PatchError):
            plan_binary_patch(fixture() + GL_ALLOWED_ORIG)

    def test_duplicate_display_init_pattern_fails(self):
        original = fixture()
        display_start = original.index(b"\x84\xc0\x0f\x85")
        extra = original[display_start:display_start + 14]
        with self.assertRaises(PatchError):
            plan_binary_patch(original + extra)


if __name__ == "__main__":
    unittest.main()
