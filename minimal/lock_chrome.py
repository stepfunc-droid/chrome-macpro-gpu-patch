#!/usr/bin/env python3
"""Explicit post-install protection for a *manually moved* patched Chrome.

Does not move, replace, launch or back up any app. Requires matching manifest
from prepare_chrome.py and matching signed framework on /Applications.
Run only after the user has tested the candidate and moved it manually.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

from patch_chrome import checked_app

APPS_CHROME = Path("/Applications/Google Chrome.app")
DOWNLOADS = Path.home() / "Downloads"
REQUIRED = {
    "allowed_gl_jump",
    "display_init_jump",
    "experimental_gl_mode_branch",
    "P5_IOSurfaceFactoryTarget",
    "P6_IOSurfaceValidateTarget_BYPASS",
    "P7_IOSurfaceBackingTarget",
}


class LockError(RuntimeError):
    pass


def run(argv):
    result = subprocess.run([str(x) for x in argv],
                            capture_output=True, text=True)
    if result.returncode:
        raise LockError(
            f"{argv[0]} exited {result.returncode}: "
            + (result.stderr or result.stdout)[-1000:])


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(4 * 1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def lock_after_manual_install(*, app=APPS_CHROME, downloads=DOWNLOADS):
    if sys.platform != "darwin" or os.geteuid() == 0:
        raise LockError("Run on macOS as the app owner (no sudo)")
    if app != APPS_CHROME or app.is_symlink():
        raise LockError("Only /Applications/Google Chrome.app may be locked")
    app, _, version, _, framework = checked_app(app)
    manifest_path = downloads / f"chrome-gpu-{version}.patch.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise LockError(f"Expected patch manifest not found: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("chrome_version") != version:
        raise LockError("Version mismatch with patch manifest")
    if set(manifest.get("patches", {})) != REQUIRED:
        raise LockError("Manifest does not list all six graphics patches")
    if manifest.get("p4_seatbelt_bypass") is not False:
        raise LockError("Manifest does not explicitly exclude P4")
    if sha256_file(framework) != manifest.get("signed_framework_sha256"):
        raise LockError("Installed Chrome differs from prepared tested candidate")
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", app])
    if not os.access(app, os.W_OK):
        raise LockError("App is not writable by this account; cannot set flags")
    print(f"[+] Verified matching, signed Chrome {version} at {app}")
    run(["/bin/chmod", "-R", "a-w", app])
    run(["/usr/bin/chflags", "uchg", app])
    root_stat = app.stat()
    if root_stat.st_mode & 0o222 or not (
        getattr(root_stat, "st_flags", 0) & getattr(stat, "UF_IMMUTABLE", 0)
    ):
        raise LockError("Unable to verify read-only/uchg protection")
    print("[+] Read-only permissions and uchg set on installed Chrome.")
    print("[!] Privileged updaters can still potentially clear this protection.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    args = parser.parse_args(argv)
    try:
        lock_after_manual_install()
        return 0
    except (LockError, OSError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
