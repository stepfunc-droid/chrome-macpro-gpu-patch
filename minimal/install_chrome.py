#!/usr/bin/env python3
"""Build Chrome GPU M157 from two fixed DMGs; install only after verification.

Usage:
  python3 minimal/install_chrome.py --install
  python3 minimal/install_chrome.py --prepare-only

No root, no SIP change, no background updater, no P4 Seatbelt bypass.
The original /Applications/Google Chrome.app is untouched until *all*
pre-install checks pass, then archived on the same volume for rollback.
"""
import argparse
from contextlib import contextmanager, ExitStack
from datetime import datetime
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile

from patch_chrome import (
    main as patch_main,
    checked_app,
    verify_official_google_app,
    verify_full_graphics_output,
)
from full_graphics_m157 import GPU_FLAGS

LATEST_DMG = Path.home() / "Downloads/googlechrome.dmg"
ANGLE_DMG = Path.home() / "Downloads/google-chrome-151-0-7922-174.dmg"
APPLICATIONS = Path("/Applications")
DESTINATION = APPLICATIONS / "Google Chrome.app"
EXPECTED_VERSION = "157.0.8103.51"
EXPECTED_DONOR = "151.0.7922.174"


class InstallationError(RuntimeError):
    pass


def call(argv, *, timeout=None):
    result = subprocess.run([str(x) for x in argv], capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        raise InstallationError(
            f"{argv[0]} exited {result.returncode}:\n"
            f"{result.stderr[-1400:]}\n{result.stdout[-800:]}"
        )
    return result.stdout


def validate_dmg(path):
    if not path.is_file() or path.is_symlink() or path.suffix.lower() != ".dmg":
        raise InstallationError(f"DMG missing or not a regular DMG file: {path}")


@contextmanager
def mounted_chrome(dmg, mount_root, expected_version):
    """Mount an image read-only; detach on success and on failure."""
    validate_dmg(dmg)
    mount_root.mkdir(parents=True, exist_ok=False)
    attached = False
    try:
        call(["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse",
              "-mountpoint", mount_root, dmg], timeout=90)
        attached = True
        app = mount_root / "Google Chrome.app"
        if app.is_symlink():
            raise InstallationError(f"Refusing symlinked mounted Chrome app: {app}")
        _, _, version, _, _ = checked_app(app)
        if version != expected_version:
            raise InstallationError(
                f"Unexpected Chrome version in {dmg.name}: "
                f"{version}; expected {expected_version}. "
                "Stop: this installer only supports the audited M157 binary."
            )
        verify_official_google_app(app)
        yield app
    finally:
        if attached:
            result = subprocess.run(["/usr/bin/hdiutil", "detach", str(mount_root)],
                                    capture_output=True, text=True)
            if result.returncode:
                print(f"[!] WARNING: Could not unmount {mount_root}: "
                      f"{result.stderr.strip()}", file=sys.stderr)


def validate_candidate(app, *, smoke=True):
    """Validate complete patch, signed nested components, and native launcher."""
    _, _, version, _, _ = checked_app(app)
    if version != EXPECTED_VERSION:
        raise InstallationError(f"Unexpected candidate version: {version}")
    verify_full_graphics_output(app)
    call(["/usr/bin/codesign", "--verify", "--deep", "--strict", app])
    # The launcher is the original upstream C entry point, which injects GPU
    # flags. A --version call validates basic framework load / AMFI launch.
    launcher = app / "Contents/MacOS/Google Chrome"
    if not launcher.is_file() or launcher.is_symlink():
        raise InstallationError("Missing or symlinked native launcher")
    if smoke:
        try:
            version_output = call([launcher, "--version"], timeout=20)
        except subprocess.TimeoutExpired as exc:
            raise InstallationError("Chrome launcher --version timed out") from exc
        if EXPECTED_VERSION not in version_output:
            raise InstallationError(
                f"Unexpected launcher --version output: {version_output[:300]!r}"
            )
    print("[+] Candidate verified: patched bytes, signature, launcher.")


def running_installed_chrome():
    """Block replacement if a browser from the installed app is running."""
    out = call(["/bin/ps", "-axo", "command"])
    return any("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" in x
               for x in out.splitlines())


def is_immutable(app):
    return bool(getattr(app.stat(), "st_flags", 0) &
                getattr(stat, "UF_IMMUTABLE", 0))


def set_readonly(app):
    """Make the installed bundle read-only and set user immutable on its root.

    This impedes unprivileged in-place updates or replacement; it is *not*
    a guarantee against a privileged updater that clears the flag.
    """
    call(["/bin/chmod", "-R", "a-w", app])
    call(["/usr/bin/chflags", "uchg", app])
    if not is_immutable(app):
        raise InstallationError("Could not verify immutable flag on installed app")
    if app.stat().st_mode & 0o222:
        raise InstallationError("Installed app remains writable")
    print("[+] Installed Chrome marked read-only and user-immutable (uchg).")


def clear_root_immutable(app):
    if app.exists() and is_immutable(app):
        call(["/usr/bin/chflags", "nouchg", app])


def unique_backup_path():
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = APPLICATIONS / f".Google Chrome.pre-GPU-{stamp}.app"
    for i in range(100):
        path = base if i == 0 else APPLICATIONS / f".Google Chrome.pre-GPU-{stamp}-{i}.app"
        if not path.exists() and not path.is_symlink():
            return path
    raise InstallationError("Could not allocate a unique Chrome backup path")


def safe_remove_pending(app):
    if not app.exists() and not app.is_symlink():
        return
    try:
        clear_root_immutable(app)
        shutil.rmtree(app)
    except OSError as exc:
        print(f"[!] Left staging app {app}: {exc}", file=sys.stderr)


def install_candidate(candidate):
    if sys.platform != "darwin" or os.geteuid() == 0:
        raise InstallationError("Run as your regular macOS user (never with sudo)")
    if not APPLICATIONS.is_dir() or DESTINATION.is_symlink():
        raise InstallationError("Unexpected /Applications destination")
    if running_installed_chrome():
        raise InstallationError(
            "Close the running /Applications/Google Chrome.app before replacing it"
        )
    if not os.access(APPLICATIONS, os.W_OK):
        raise InstallationError(
            "No permission to modify /Applications. Original Chrome untouched."
        )
    validate_candidate(candidate)

    # Stage on the SAME volume as the destination; no original app changes
    # until the signed, validated pending copy is ready.
    with tempfile.TemporaryDirectory(prefix=".chrome-gpu-install-control-") as _:
        pending = APPLICATIONS / f".Google Chrome.gpu-pending-{os.getpid()}.app"
        if pending.exists() or pending.is_symlink():
            raise InstallationError(f"Refusing existing pending path: {pending}")
        backup = None
        old_locked = False
        moved_new = False
        moved_old = False
        try:
            print("[*] Copying verified candidate to /Applications staging...")
            call(["/usr/bin/ditto", "--norsrc", candidate, pending])
            validate_candidate(pending)
            if DESTINATION.exists():
                old_locked = is_immutable(DESTINATION)
                backup = unique_backup_path()
            # Last chance to reject a concurrent browser launch.
            if running_installed_chrome():
                raise InstallationError("Chrome started while staging: aborting")
            if backup:
                # Unset only the top-level immutable flag after ALL
                # pre-install checks have passed.
                clear_root_immutable(DESTINATION)
                DESTINATION.rename(backup)
                moved_old = True
            pending.rename(DESTINATION)
            moved_new = True
            validate_candidate(DESTINATION, smoke=False)
            set_readonly(DESTINATION)
            # Only now is installation committed; retain rollback backup.
            print(f"[+] Installed: {DESTINATION}")
            if backup:
                print(f"[+] Previous Chrome retained as rollback backup: {backup}")
            print("[!] The app-level read-only/uchg protection is not an "
                  "absolute block against privileged Google Update services.")
            return backup
        except Exception:
            print("[!] Install failed. Restoring previous Chrome if it was moved...",
                  file=sys.stderr)
            if moved_new and DESTINATION.exists():
                clear_root_immutable(DESTINATION)
                # Avoid removing a candidate for which a user might want logs.
                if not pending.exists():
                    DESTINATION.rename(pending)
            if moved_old and backup and backup.exists() and not DESTINATION.exists():
                backup.rename(DESTINATION)
                if old_locked:
                    call(["/usr/bin/chflags", "uchg", DESTINATION])
            raise
        finally:
            safe_remove_pending(pending)


def build_from_dmgs(workdir):
    with ExitStack() as stack:
        source = stack.enter_context(mounted_chrome(
            LATEST_DMG, workdir / "mount-latest", EXPECTED_VERSION))
        donor = stack.enter_context(mounted_chrome(
            ANGLE_DMG, workdir / "mount-151", EXPECTED_DONOR))
        output = workdir / "Google Chrome.app"
        print("[*] Building M157 from both verified DMGs in private staging...")
        status = patch_main([
            "--source", str(source),
            "--angle-from", str(donor),
            "--output", str(output),
            "--experimental-version",
            "--full-graphics-compat",
            "--inject-launcher",
            "--apply",
        ])
        if status:
            raise InstallationError(f"Patch/signing failed with exit status {status}")
        validate_candidate(output)
        return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--install", action="store_true",
                      help="Build, verify, back up and replace /Applications Chrome")
    mode.add_argument("--prepare-only", action="store_true",
                      help="Build a fully patched copy in Downloads; do not install")
    args = parser.parse_args(argv)
    if sys.platform != "darwin" or os.geteuid() == 0:
        parser.error("Requires macOS and your normal user account (no sudo)")
    if args.install and running_installed_chrome():
        parser.error("Close the running /Applications Chrome first")

    downloads = Path.home() / "Downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    # Temporary location under HOME, satisfying patcher's no-root and
    # no-overwrite preflight. Intentional retention in --prepare-only mode.
    workdir = Path(tempfile.mkdtemp(prefix=".chrome-gpu-build-", dir=downloads))
    keep_workdir = False
    try:
        candidate = build_from_dmgs(workdir)
        if args.prepare_only:
            # In prepare-only mode the tested candidate is retained for GUI
            # testing, and never replaces the installed browser.
            keep_workdir = True
            print(f"[+] Prepared GPU Chrome: {candidate}")
            print("[*] Launch normally to verify rendering, then use --install.")
            return 0
        backup = install_candidate(candidate)
        # Avoid generating an updater service. A regular launch of
        # /Applications/Google Chrome.app uses the embedded flags launcher.
        print("[+] Complete. Launch Google Chrome normally from Applications.")
        print("[*] Compatibility flags are injected by the signed launcher.")
        return 0
    except (InstallationError, OSError, ValueError, RuntimeError) as exc:
        print(f"[!] ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        if not keep_workdir:
            try:
                shutil.rmtree(workdir)
            except OSError as exc:
                print(f"[!] Temporary staging retained at {workdir}: {exc}",
                      file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
