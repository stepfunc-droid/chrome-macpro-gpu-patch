#!/usr/bin/env python3
"""Synthetic byte-pattern tests; does not test actual Chrome or GPU hardware."""
import struct
import stat
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from patch_chrome import (GL_ALLOWED_ORIG, PatchError, inspect_binary_patterns,
                          plan_binary_patch, strip_codesign_detritus_from_copy,
                          copy_angle_without_flags)


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
        extra = original[display_start:display_start + 16]
        with self.assertRaises(PatchError):
            plan_binary_patch(original + extra)

    def test_m157_both_distinct_patterns_prefers_specific_one(self):
        # Actual M157 diagnostic: one specific ANGLE hit, one unrelated
        # broad legacy hit. They must not be counted as two candidates.
        broad = (b"\x84\xc0\x0f\x85" + struct.pack("<i", -6005)
                 + b"\x83\x7d\x8c\x00\x0f\x85" + b"\xbb" * 16)
        original = fixture() + b"\x7f" * 24 + broad
        modified, positions = plan_binary_patch(original)
        specific_offset = original.index(b"\x84\xc0\x0f\x85") + 2
        self.assertEqual(positions["display_init_jump"], specific_offset)
        self.assertEqual(modified[-len(broad):], original[-len(broad):],
                         "unrelated legacy-looking instruction must remain untouched")

    def test_legacy_fallback_when_specific_absent(self):
        broad = (b"\x84\xc0\x0f\x85" + struct.pack("<i", 42)
                 + b"\x83\x7d\x8c\x00\x0f\x85")
        original = b"\xcc" * 32 + GL_ALLOWED_ORIG + b"\xff" * 24 + broad
        modified, positions = plan_binary_patch(original)
        self.assertEqual(modified[positions["display_init_jump"]:positions["display_init_jump"]+6],
                         b"\xe9" + struct.pack("<i", 43) + b"\x90")

    def test_sanitize_only_disallowed_metadata_in_staged_copy(self):
        stage = "/tmp/private-clone/Google Chrome.app"
        attrs = {
            stage: "com.apple.quarantine\ncom.apple.FinderInfo\n",
            stage + "/Contents": "com.apple.ResourceFork\ncom.apple.provenance\n",
            stage + "/Contents/Info.plist": "com.apple.quarantine\n",
        }
        removed = []

        def fake_cmd(arguments):
            self.assertEqual(arguments[0], "/usr/bin/xattr")
            if len(arguments) == 2:
                self.assertIn(arguments[1], attrs)
                return attrs[arguments[1]]
            self.assertEqual(arguments[1], "-d")
            removed.append((arguments[2], arguments[3]))
            return ""

        with mock.patch("patch_chrome.os.walk", return_value=[
            (stage, ["Contents"], ["Contents/Info.plist"])
        ]), mock.patch("patch_chrome.os.path.islink", return_value=False), \
             mock.patch("patch_chrome.cmd", side_effect=fake_cmd):
            count = strip_codesign_detritus_from_copy(stage)
        self.assertEqual(count, 2)
        self.assertEqual(removed, [
            ("com.apple.FinderInfo", stage),
            ("com.apple.ResourceFork", stage + "/Contents"),
        ])

    def test_sanitize_does_not_follow_symlink(self):
        stage = "/tmp/private-clone/Google Chrome.app"
        link = stage + "/Contents/alias"
        called = []

        def fake_cmd(arguments):
            called.append(arguments)
            return ""

        with mock.patch("patch_chrome.os.walk", return_value=[
            (stage, ["Contents"], []),
            (stage + "/Contents", [], ["alias"]),
        ]), mock.patch("patch_chrome.os.path.islink",
                      side_effect=lambda path: path == link), \
             mock.patch("patch_chrome.cmd", side_effect=fake_cmd):
            count = strip_codesign_detritus_from_copy(stage)
        self.assertEqual(count, 0)
        self.assertNotIn(["/usr/bin/xattr", link], called)

    def test_angle_copy_does_not_copy_donor_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "donor.dylib"
            dest = Path(tmp) / "staged.dylib"
            src.write_bytes(b"test ANGLE bytes")
            src.chmod(0o755)
            with mock.patch("patch_chrome.shutil.copy2", side_effect=AssertionError(
                    "copy2 would preserve donor BSD flags")):
                result = copy_angle_without_flags(src, dest)
            self.assertEqual(result, dest)
            self.assertEqual(dest.read_bytes(), src.read_bytes())
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o755)

    def test_angle_copy_refuses_staged_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "donor.dylib"
            outside = Path(tmp) / "outside-file"
            dest = Path(tmp) / "staged.dylib"
            src.write_bytes(b"donor")
            outside.write_bytes(b"outside")
            dest.symlink_to(outside)
            with self.assertRaises(PatchError):
                copy_angle_without_flags(src, dest)
            self.assertEqual(outside.read_bytes(), b"outside")

    def test_diagnostic_reports_missing_display_match(self):
        report = "\n".join(inspect_binary_patterns(GL_ALLOWED_ORIG + b"\x00" * 64))
        self.assertIn("Display pattern 1: 0 match(es)", report)
        self.assertIn("Display pattern 2: 0 match(es)", report)

    def test_diagnostic_reports_known_signature(self):
        report = "\n".join(inspect_binary_patterns(fixture()))
        self.assertIn("Display pattern 1: 1 match(es)", report)
        self.assertIn("OpenGL allow check: exact=1", report)


if __name__ == "__main__":
    unittest.main()
