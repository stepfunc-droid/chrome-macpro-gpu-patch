#!/usr/bin/env python3
"""Verify locking is explicit and cannot target the wrong installed Chrome."""
from pathlib import Path
import json
import tempfile
import unittest
from unittest import mock
import lock_chrome


class LockChromeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dl = Path(self.tmp.name)
        self.version = "157.0.8103.51"
        self.file = self.dl / f"chrome-gpu-{self.version}.patch.json"
        self.file.write_text(json.dumps({
            "chrome_version": self.version,
            "patches": {k: "0xa" for k in lock_chrome.REQUIRED},
            "p4_seatbelt_bypass": False,
            "signed_framework_sha256": "f" * 64,
        }), encoding="utf-8")
        self.app = lock_chrome.APPS_CHROME

    def test_wrong_install_path_fails_before_commands(self):
        with mock.patch.object(lock_chrome.sys, "platform", "darwin"), \
             mock.patch.object(lock_chrome.os, "geteuid", return_value=501), \
             mock.patch.object(lock_chrome, "run") as run:
            with self.assertRaisesRegex(lock_chrome.LockError,
                                        "Only /Applications"):
                lock_chrome.lock_after_manual_install(app=self.dl,
                                                       downloads=self.dl)
            run.assert_not_called()

    def test_wrong_signed_binary_refuses_permissions_change(self):
        with mock.patch.object(lock_chrome.sys, "platform", "darwin"), \
             mock.patch.object(lock_chrome.os, "geteuid", return_value=501), \
             mock.patch.object(lock_chrome.Path, "is_symlink", return_value=False), \
             mock.patch.object(lock_chrome, "checked_app", return_value=(
                 self.app, 157, self.version, self.app, self.dl / "framework")), \
             mock.patch.object(lock_chrome, "sha256_file", return_value="0"*64), \
             mock.patch.object(lock_chrome, "run") as run:
            with self.assertRaisesRegex(lock_chrome.LockError,
                                        "differs from prepared"):
                lock_chrome.lock_after_manual_install(downloads=self.dl)
            run.assert_not_called()

    def test_unapproved_p4_in_manifest_refused(self):
        obj = json.loads(self.file.read_text())
        obj["p4_seatbelt_bypass"] = True
        self.file.write_text(json.dumps(obj))
        with mock.patch.object(lock_chrome.sys, "platform", "darwin"), \
             mock.patch.object(lock_chrome.os, "geteuid", return_value=501), \
             mock.patch.object(lock_chrome.Path, "is_symlink", return_value=False), \
             mock.patch.object(lock_chrome, "checked_app", return_value=(
                 self.app, 157, self.version, self.app, self.dl / "framework")), \
             mock.patch.object(lock_chrome, "run") as run:
            with self.assertRaisesRegex(lock_chrome.LockError, "exclude P4"):
                lock_chrome.lock_after_manual_install(downloads=self.dl)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
