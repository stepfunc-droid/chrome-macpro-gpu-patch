#!/usr/bin/env python3
"""Transactional installer tests; simulate filesystem only, no macOS writes."""
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import install_chrome as installer


class TransactionalInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.apps = root / "Applications"
        self.apps.mkdir()
        self.original = self.apps / "Google Chrome.app"
        self.original.mkdir()
        (self.original / "marker.txt").write_text("original")
        self.candidate = root / "candidate"
        self.candidate.mkdir()
        (self.candidate / "marker.txt").write_text("candidate")
        self.mocks = [
            mock.patch.object(installer, "APPLICATIONS", self.apps),
            mock.patch.object(installer, "DESTINATION", self.original),
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(installer.os, "geteuid", return_value=501),
            mock.patch.object(installer.os, "access", return_value=True),
            mock.patch.object(installer, "running_installed_chrome",
                              return_value=False),
            mock.patch.object(installer, "is_immutable", return_value=False),
        ]
        for p in self.mocks:
            p.start()
            self.addCleanup(p.stop)

    def _fake_call(self, argv, *, timeout=None):
        if str(argv[0]) == "/usr/bin/ditto":
            shutil.copytree(Path(argv[-2]), Path(argv[-1]))
        return ""

    def test_prevalidation_failure_never_changes_original(self):
        with mock.patch.object(installer, "validate_candidate",
                               side_effect=installer.InstallationError("bad signature")):
            with self.assertRaisesRegex(installer.InstallationError, "bad signature"):
                installer.install_candidate(self.candidate)
        self.assertEqual((self.original / "marker.txt").read_text(), "original")
        self.assertEqual(len(list(self.apps.iterdir())), 1)

    def test_verified_candidate_replaces_old_and_preserves_backup(self):
        with mock.patch.object(installer, "validate_candidate"), \
             mock.patch.object(installer, "call", side_effect=self._fake_call), \
             mock.patch.object(installer, "set_readonly") as readonly:
            backup = installer.install_candidate(self.candidate)
        self.assertEqual((self.original / "marker.txt").read_text(), "candidate")
        self.assertEqual((backup / "marker.txt").read_text(), "original")
        self.assertTrue(backup.name.startswith(".Google Chrome.pre-GPU-"))
        readonly.assert_called_once_with(self.original)
        self.assertFalse(any("pending" in p.name for p in self.apps.iterdir()))

    def test_readonly_failure_rolls_back_original(self):
        with mock.patch.object(installer, "validate_candidate"), \
             mock.patch.object(installer, "call", side_effect=self._fake_call), \
             mock.patch.object(installer, "set_readonly",
                               side_effect=installer.InstallationError("chmod failed")):
            with self.assertRaisesRegex(installer.InstallationError, "chmod failed"):
                installer.install_candidate(self.candidate)
        self.assertEqual((self.original / "marker.txt").read_text(), "original")
        self.assertFalse(any("pending" in p.name for p in self.apps.iterdir()))

    def test_running_chrome_blocks_any_copy(self):
        with mock.patch.object(installer, "running_installed_chrome",
                               return_value=True), \
             mock.patch.object(installer, "call") as call:
            with self.assertRaisesRegex(installer.InstallationError, "Close the running"):
                installer.install_candidate(self.candidate)
            call.assert_not_called()
        self.assertEqual((self.original / "marker.txt").read_text(), "original")

    def test_locked_original_relocked_if_rename_fails(self):
        original_rename = Path.rename
        def fail_on_original(path, target):
            if path == self.original:
                raise OSError("rename denied")
            return original_rename(path, target)
        commands = []
        def call(argv, *, timeout=None):
            commands.append([str(a) for a in argv])
            return self._fake_call(argv, timeout=timeout)
        with mock.patch.object(installer, "is_immutable", return_value=True), \
             mock.patch.object(installer, "validate_candidate"), \
             mock.patch.object(installer, "call", side_effect=call), \
             mock.patch.object(Path, "rename", autospec=True,
                               side_effect=fail_on_original):
            with self.assertRaisesRegex(OSError, "rename denied"):
                installer.install_candidate(self.candidate)
        self.assertEqual((self.original / "marker.txt").read_text(), "original")
        self.assertEqual(
            [command[1] for command in commands
             if command[0] == "/usr/bin/chflags"
             and command[-1] == str(self.original)],
            ["nouchg", "uchg"]
        )

    def test_wrong_dmg_version_detaches(self):
        root = Path(self.tmp.name) / "mount"
        dmg = Path(self.tmp.name) / "target.dmg"
        dmg.write_bytes(b"fake -- not mounted")
        commands = []
        def call(argv, *, timeout=None):
            commands.append([str(x) for x in argv])
            return ""
        with mock.patch.object(installer, "call", side_effect=call), \
             mock.patch.object(installer.subprocess, "run",
                               return_value=mock.Mock(returncode=0, stderr="")), \
             mock.patch.object(installer, "checked_app", return_value=(
                 root / "Google Chrome.app", 158, "158.0.1.2", None, None)), \
             mock.patch.object(installer, "verify_official_google_app"):
            with self.assertRaisesRegex(installer.InstallationError, "Unexpected Chrome version"):
                with installer.mounted_chrome(dmg, root, installer.EXPECTED_VERSION):
                    pass
        self.assertIn("-readonly", commands[0])
        self.assertEqual(commands[-1][:2], ["/usr/bin/hdiutil", "detach"])

    def test_fixed_dmgs_are_used(self):
        self.assertEqual(installer.LATEST_DMG.name, "googlechrome.dmg")
        self.assertEqual(installer.ANGLE_DMG.name,
                         "google-chrome-151-0-7922-174.dmg")
        self.assertEqual(installer.EXPECTED_VERSION, "157.0.8103.51")


if __name__ == "__main__":
    unittest.main()
