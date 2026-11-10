#!/usr/bin/env python3
"""New workflow tests: prepare in Downloads, never touch /Applications."""
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from adaptive_graphics import scan_and_patch, verify_patched_regions
from full_graphics_m157 import PATCHES, GPU_FLAGS, GraphicsCompatError
from patch_chrome import GL_ALLOWED_ORIG, M157_P3_ORIGINAL
import prepare_chrome


def synthetic_unvalidated_framework():
    # Synthetic assembly sequences, NOT evidence that Chrome 158 works.
    p2 = (b"\x84\xc0\x0f\x85" + struct.pack("<i", 37) +
          bytes.fromhex("48 b8 09 00 00 00 03 00"))
    return (b"\xcc" * 80 + GL_ALLOWED_ORIG + b"\xcc" * 80
            + p2 + b"\xcc" * 80
            + M157_P3_ORIGINAL + b"\xcc" * 80
            + PATCHES[0][2] + b"\xcc" * 80
            + PATCHES[1][2] + b"\xcc" * 80
            + PATCHES[2][2] + b"\xcc" * 80)


class AdaptiveCompatibilityTests(unittest.TestCase):
    def test_unknown_version_can_pass_structural_check(self):
        original = synthetic_unvalidated_framework()
        patched, offsets, confidence = scan_and_patch(
            original, version="158.0.8000.12", sha="arbitrary")
        self.assertEqual(confidence, "STRUCTURAL_ONLY_UNTESTED")
        self.assertEqual(len(offsets), 6)
        self.assertEqual(len(patched), len(original))
        self.assertEqual(patched[offsets["P6_IOSurfaceValidateTarget_BYPASS"]:
                                 offsets["P6_IOSurfaceValidateTarget_BYPASS"]+3],
                         b"\xb0\x01\xc3")
        self.assertIn("P5_IOSurfaceFactoryTarget", offsets)
        self.assertNotIn("P4", " ".join(offsets.keys()))

    def test_unmatched_future_version_refuses_patch(self):
        orig = synthetic_unvalidated_framework()
        deleted_p6 = orig.replace(PATCHES[1][2], b"\xcc" * len(PATCHES[1][2]))
        with self.assertRaisesRegex(GraphicsCompatError, "P6"):
            scan_and_patch(deleted_p6, version="159.0.0.1", sha="new")
        self.assertNotEqual(deleted_p6, orig)

    def test_ambiguous_future_signature_refuses_patch(self):
        orig = synthetic_unvalidated_framework() + PATCHES[2][2]
        with self.assertRaisesRegex(GraphicsCompatError, "P7"):
            scan_and_patch(orig, version="158.0.0.1", sha="new")

    def test_future_mode_regression_refuses_patch(self):
        orig = synthetic_unvalidated_framework()
        # Change the source immediate from 3 to 4; cannot assume enums.
        altered = orig.replace(M157_P3_ORIGINAL,
                               M157_P3_ORIGINAL.replace(
                                   bytes.fromhex("c7 45 ac 03 00 00 00"),
                                   bytes.fromhex("c7 45 ac 04 00 00 00")))
        with self.assertRaisesRegex(GraphicsCompatError, "P3"):
            scan_and_patch(altered, version="158.0.0.1", sha="new")

    def test_verify_only_6_regions_survive_re_signing(self):
        orig = synthetic_unvalidated_framework()
        patched, offsets, _ = scan_and_patch(
            orig, version="158.0.8000.12", sha="new")
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "framework"
            file.write_bytes(patched + b"\x99" * 45)
            self.assertTrue(verify_patched_regions(file, patched, offsets))
            with file.open("r+b") as stream:
                stream.seek(offsets["P5_IOSurfaceFactoryTarget"] + 2)
                stream.write(b"\x00")
            with self.assertRaisesRegex(GraphicsCompatError, "P5"):
                verify_patched_regions(file, patched, offsets)

    def test_shell_contains_full_known_workarounds(self):
        script = prepare_chrome.shell_script(
            "Google Chrome.app", "158.0.8000.12")
        self.assertIn('SCRIPT_DIR=', script)
        self.assertIn('exec "$BIN"', script)
        self.assertIn('Google Chrome.app', script)
        self.assertNotIn('Chrome GPU 158.0.8000.12.app', script)
        for flag in GPU_FLAGS:
            self.assertIn(flag, script)
        self.assertNotIn("--no-sandbox", script)
        self.assertNotIn("/Applications", script)

    def test_dmg_paths_stable_not_target_version(self):
        self.assertEqual(prepare_chrome.TARGET_DMG.name, "googlechrome.dmg")
        self.assertEqual(prepare_chrome.ANGLE_DMG.name,
                         "google-chrome-151-0-7922-174.dmg")
        self.assertFalse(hasattr(prepare_chrome, "EXPECTED_VERSION"))
        self.assertFalse(hasattr(prepare_chrome, "DESTINATION"))

    def test_mount_detaches_even_when_app_inspection_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            dmg = base / "test.dmg"
            dmg.write_bytes(b"fixture")
            calls = []
            def command(argv, **kwargs):
                calls.append([str(x) for x in argv])
                return ""
            with mock.patch.object(prepare_chrome, "command",
                                   side_effect=command), \
                 mock.patch.object(prepare_chrome, "checked_app",
                                   side_effect=ValueError("bad Chrome")), \
                 mock.patch.object(prepare_chrome.subprocess, "run",
                                   return_value=mock.Mock(returncode=0,
                                                          stderr="")):
                with self.assertRaisesRegex(ValueError, "bad Chrome"):
                    with prepare_chrome.mount_dmg(
                        dmg, base / "mount"):
                        pass
            self.assertIn("-readonly", calls[0])

    def test_mount_dmg_does_not_verify_unclean_vendor_app(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            dmg = base / "source.dmg"
            dmg.write_bytes(b"stub")
            with mock.patch.object(prepare_chrome, "command"), \
                 mock.patch.object(prepare_chrome, "checked_app"), \
                 mock.patch.object(prepare_chrome, "verify_official_google_app") as verify, \
                 mock.patch.object(prepare_chrome.subprocess, "run",
                                   return_value=mock.Mock(returncode=0, stderr="")):
                with prepare_chrome.mount_dmg(dmg, base / "mount"):
                    verify.assert_not_called()
                verify.assert_not_called()

    def test_trusted_copy_strips_metadata_before_google_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            donor = root / "mounted/Google Chrome.app"
            candidate = root / "copy/Google Chrome.app"
            framework = root / "framework"
            framework.write_bytes(b"original framework for hash test")
            operations = []
            with mock.patch.object(
                 prepare_chrome, "command",
                 side_effect=lambda *a, **kw: operations.append("ditto")), \
                 mock.patch.object(
                     prepare_chrome, "checked_app",
                     return_value=(candidate, 151, "151.0.7922.174",
                                   framework, framework)), \
                 mock.patch.object(
                     prepare_chrome, "strip_codesign_detritus_from_copy",
                     side_effect=lambda *a: operations.append("strip")), \
                 mock.patch.object(
                     prepare_chrome, "verify_official_google_app",
                     side_effect=lambda *a: operations.append("verify")):
                prepare_chrome.trusted_copy_from_dmg(donor, candidate)
            self.assertEqual(operations, ["ditto", "strip", "verify"])

    def test_trusted_copy_hash_mismatch_stops_before_signature_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            framework = root / "framework"
            framework.write_bytes(b"the wrong content")
            with mock.patch.object(prepare_chrome, "command"), \
                 mock.patch.object(prepare_chrome, "checked_app",
                     return_value=(root, 157, "157.0.8103.51",
                                   root, framework)), \
                 mock.patch.object(
                     prepare_chrome, "strip_codesign_detritus_from_copy") as strip, \
                 mock.patch.object(
                     prepare_chrome, "verify_official_google_app") as verify:
                with self.assertRaisesRegex(prepare_chrome.PreparationError,
                                            "differs from DMG"):
                    prepare_chrome.trusted_copy_from_dmg(
                        root, root / "out.app", expected_sha="0" * 64)
                strip.assert_not_called()
                verify.assert_not_called()

    def test_legacy_installer_no_longer_auto_installs(self):
        from install_chrome import prepare_main
        self.assertIs(prepare_main, prepare_chrome.main)


if __name__ == "__main__":
    unittest.main()
