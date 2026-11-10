#!/usr/bin/env python3
"""Signing-plan tests: no real codesign, Chrome download, or macOS requirement."""
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock

from signing import (BRANDED_KEYS, JIT_ENTITLEMENT, MAIN_CAPABILITIES,
                     SigningError, helper_entitlements, sign_test_copy)


def fake_app(root):
    stage = Path(root) / ".chrome-gl-test-unit"
    app = stage / "Google Chrome.app"
    fw = app / "Contents/Frameworks/Google Chrome Framework.framework"
    ver = fw / "Versions/157.0.8103.51"
    (ver / "Libraries").mkdir(parents=True)
    (ver / "Libraries/libEGL.dylib").write_bytes(b"TEST")
    helpers = ver / "Helpers"
    helpers.mkdir()
    for name in ("Google Chrome Helper.app", "Google Chrome Helper (GPU).app",
                 "Google Chrome Helper (Renderer).app"):
        (helpers / name).mkdir()
    (helpers / "chrome_crashpad_handler").write_bytes(b"TEST")
    (fw / "Versions/Current").symlink_to("157.0.8103.51")
    return app


class SigningTests(unittest.TestCase):
    def test_helper_roles_are_narrow(self):
        self.assertEqual(helper_entitlements("Google Chrome Helper.app"), {})
        self.assertEqual(helper_entitlements("Google Chrome Helper (Renderer).app"),
                         {JIT_ENTITLEMENT: True})
        self.assertEqual(helper_entitlements("Google Chrome Helper (GPU).app"),
                         {JIT_ENTITLEMENT: True})
        self.assertEqual(helper_entitlements("Google Chrome Helper (Aperitif Renderer).app"),
                         {JIT_ENTITLEMENT: True})

    def test_only_staged_copy_and_sign_inside_out(self):
        with tempfile.TemporaryDirectory() as root:
            app = fake_app(root)
            calls = []
            content = {}

            def record_sign(path, *, entitlements=None, runtime=False):
                calls.append((str(path), runtime, entitlements is not None))
                if entitlements:
                    content[Path(path).name] = plistlib.loads(Path(entitlements).read_bytes())

            with mock.patch("signing.sign", side_effect=record_sign), \
                 mock.patch("signing.run") as run:
                sign_test_copy(app)
                run.assert_called_once()
            names = [Path(x[0]).name for x in calls]
            self.assertEqual(names[0], "libEGL.dylib")
            self.assertEqual(names[-2:], ["Google Chrome Framework.framework", "Google Chrome.app"])
            self.assertIn("Google Chrome Helper (GPU).app", names)
            self.assertIn("Google Chrome Helper (Renderer).app", names)
            self.assertTrue(calls[-1][1])
            self.assertEqual(content["Google Chrome.app"], {s: True for s in MAIN_CAPABILITIES})
            self.assertEqual(content["Google Chrome Helper (GPU).app"],
                             {JIT_ENTITLEMENT: True})
            self.assertEqual(content["Google Chrome Helper (Renderer).app"],
                             {JIT_ENTITLEMENT: True})
            self.assertFalse(set(content["Google Chrome.app"]) & set(BRANDED_KEYS))

    def test_refuses_unstaged_app(self):
        with tempfile.TemporaryDirectory() as root:
            app = fake_app(root)
            with self.assertRaises(SigningError):
                sign_test_copy(app.parent / "Unrelated.app")

    def test_refuses_unreviewed_xpc(self):
        with tempfile.TemporaryDirectory() as root:
            app = fake_app(root)
            nested = app / "Contents/XPCServices"
            nested.mkdir()
            (nested / "something.xpc").mkdir()
            with mock.patch("signing.sign"), mock.patch("signing.run"):
                with self.assertRaises(SigningError):
                    sign_test_copy(app)


if __name__ == "__main__":
    unittest.main()
