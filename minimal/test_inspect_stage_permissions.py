#!/usr/bin/env python3
"""Read-only staging diagnostics: synthetic tests, no macOS required."""
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from inspect_stage_permissions import inspect_stage


class StagePermissionsTests(unittest.TestCase):
    def test_inspection_only_walks_staged_paths(self):
        with tempfile.TemporaryDirectory() as d:
            stage = Path(d) / ".chrome-gl-test-abcdef"
            app = stage / "Google Chrome.app"
            ver = app / "Contents/Frameworks/Google Chrome Framework.framework/Versions"
            actual = ver / "157.0.8103.51"
            (actual / "Libraries").mkdir(parents=True)
            (ver / "Current").symlink_to(actual.name)
            with mock.patch("inspect_stage_permissions.inspect_path") as inspect:
                inspect_stage(app)
            self.assertEqual(inspect.call_count, 6)
            self.assertEqual(inspect.call_args_list[-1].args[0],
                             ver / "Current/Libraries/libGLESv2.dylib")

    def test_rejects_non_staging_app(self):
        with tempfile.TemporaryDirectory() as d:
            app = Path(d) / "Google Chrome.app"
            app.mkdir()
            with self.assertRaises(ValueError):
                inspect_stage(app)


if __name__ == "__main__":
    unittest.main()
