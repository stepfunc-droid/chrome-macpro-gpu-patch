#!/usr/bin/env python3
"""Prepare a GPU-patched Chrome in ~/Downloads from two fixed DMG images.

Never changes /Applications, SIP, installed Chrome, or background services.
Target Chrome VERSION is discovered from googlechrome.dmg, NOT hardcoded.
An unknown version may be prepared only if *all six* anchored instruction
checks pass; it remains unverified until the user tests GPU rendering.
"""
import argparse
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
import re
from pathlib import Path
import plistlib
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

from patch_chrome import (
    PatchError, checked_app, verify_official_google_app,
    strip_codesign_detritus_from_copy, copy_angle_without_flags, LIBS
)
from signing import sign_test_copy, SigningError
from full_graphics_m157 import GPU_FLAGS, GraphicsCompatError
from adaptive_graphics import scan_and_patch, verify_patched_regions


DOWNLOADS = Path.home() / "Downloads"
TARGET_DMG = DOWNLOADS / "googlechrome.dmg"
ANGLE_DMG = DOWNLOADS / "google-chrome-151-0-7922-174.dmg"


class PreparationError(RuntimeError):
    pass


def command(args, *, timeout=None):
    result = subprocess.run([str(a) for a in args],
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise PreparationError(
            f"{args[0]} failed ({result.returncode}): "
            + (result.stderr or result.stdout)[-1500:])
    return result.stdout.strip()


@contextmanager
def mount_dmg(dmg, mountpoint):
    if not dmg.is_file() or dmg.is_symlink():
        raise PreparationError(f"DMG missing or symlinked: {dmg}")
    mountpoint.mkdir(parents=True, exist_ok=False)
    mounted = False
    try:
        command(["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse",
                 "-mountpoint", str(mountpoint), str(dmg)], timeout=90)
        mounted = True
        app = mountpoint / "Google Chrome.app"
        if app.is_symlink():
            raise PreparationError(f"Unexpected symlink app in {dmg}")
        # A read-only mounted Chrome DMG may expose FinderInfo/resource-fork
        # xattrs that make codesign --verify --deep --strict fail.  Never
        # remove metadata from the mounted source.  Verify the official
        # signature only on a cleaned ditto --norsrc *copy* below.
        checked_app(app)
        yield app
    finally:
        if mounted:
            result = subprocess.run(
                ["/usr/bin/hdiutil", "detach", str(mountpoint)],
                capture_output=True, text=True)
            if result.returncode:
                print(f"WARNING: Could not detach {dmg}: "
                      f"{result.stderr.strip()}", file=sys.stderr)


def shell_script(app_name, version, signed_framework_hash=None):
    """A launch script beside the app, with a disposable independent profile.

    It intentionally supplies the SAME graphics arguments that worked on
    the user's original M157 test. A normal Finder launch would not inject
    those flags; use the script when testing.
    """
    prefix = shlex.quote(app_name)
    # Use shell-safe single-quoted basename, not interpolation into quotes.
    lines = [
        "#!/bin/bash",
        "set -e",
        'SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"',
        f"APP=\"$SCRIPT_DIR/\"{prefix}",
        'BIN="$APP/Contents/MacOS/Google Chrome"',
    ]
    if signed_framework_hash:
        if not re.fullmatch(r"[0-9a-f]{64}", signed_framework_hash):
            raise PreparationError("Invalid framework SHA256 for test launcher")
        lines.extend([
            'if [ ! -x "$BIN" ]; then',
            '  APP="/Applications/Google Chrome.app"',
            '  BIN="$APP/Contents/MacOS/Google Chrome"',
            '  FW="$APP/Contents/Frameworks/Google Chrome Framework.framework/Versions/Current/Google Chrome Framework"',
            '  if [ ! -x "$BIN" ] || [ ! -f "$FW" ]; then',
            '    echo "Prepared Chrome not found in Downloads or Applications" >&2',
            '    exit 1',
            '  fi',
            '  ACTUAL_HASH=$(/usr/bin/shasum -a 256 "$FW")',
            '  ACTUAL_HASH=${ACTUAL_HASH%% *}',
            f'  if [ "$ACTUAL_HASH" != "{signed_framework_hash}" ]; then',
            '    echo "Applications Chrome does not match the verified GPU patch" >&2',
            '    exit 1',
            '  fi',
            'fi',
        ])
    else:
        lines.extend([
            'if [ ! -x "$BIN" ]; then',
            '  echo "Cannot find Chrome executable: $BIN" >&2',
            "  exit 1",
            "fi",
        ])
    lines.extend([
        'exec "$BIN" \\',
        f'  --user-data-dir="$HOME/Downloads/Chrome-GPU-{version}-Profile" \\',
    ])
    for flag in GPU_FLAGS:
        lines.append("  " + shlex.quote(flag) + " \\")
    lines.extend([
        '  --no-first-run "$@"',
        "",
    ])
    return "\n".join(lines)


def validate_stage(stage, expected, positions, version):
    app, _, staged_version, _, binary = checked_app(stage)
    if staged_version != version:
        raise PreparationError(
            f"Staged Chrome changed version: {staged_version} != {version}"
        )
    verify_patched_regions(binary, expected, positions)
    command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)])
    executable = stage / "Contents/MacOS/Google Chrome"
    try:
        output = command([str(executable), "--version"], timeout=20)
    except subprocess.TimeoutExpired as exc:
        raise PreparationError("Staged Chrome --version timed out") from exc
    if version not in output:
        raise PreparationError("Chrome smoke test returned unexpected version: " + output)
    print("[+] Candidate verified: all six code regions, codesign and --version.")


def prepare(*, check_only=False):
    if sys.platform != "darwin" or os.geteuid() == 0:
        raise PreparationError("Run on macOS as your normal account (no sudo)")
    if not DOWNLOADS.is_dir():
        raise PreparationError(f"Downloads directory not found: {DOWNLOADS}")
    working = Path(tempfile.mkdtemp(prefix=".chrome-gpu-build-", dir=DOWNLOADS))
    staged_root = working / ".chrome-gl-test-candidate"
    stage = staged_root / "Google Chrome.app"
    published = []
    try:
        with ExitStack() as stack:
            target = stack.enter_context(mount_dmg(TARGET_DMG, working / "target"))
            donor = stack.enter_context(mount_dmg(ANGLE_DMG, working / "angle151"))
            _, target_milestone, version, _, target_binary = checked_app(target)
            if not re.fullmatch(r"[0-9]+(?:[.][0-9]+){2,3}", version):
                raise PreparationError(f"Invalid Chrome version string: {version!r}")
            _, donor_milestone, donor_version, donor_fw, _ = checked_app(donor)
            if donor_milestone != 151:
                raise PreparationError(
                    f"Chrome 151 DMG contains unexpected version {donor_version}"
                )
            original = target_binary.read_bytes()
            digest = hashlib.sha256(original).hexdigest()
            print(f"Target from {TARGET_DMG.name}: Chrome {version}")
            print(f"Source framework SHA256: {digest}")
            print(f"ANGLE donor from {ANGLE_DMG.name}: Chrome {donor_version}")
            try:
                modified, offsets, confidence = scan_and_patch(
                    original, version=version, sha=digest)
            except (GraphicsCompatError, PatchError) as exc:
                raise PreparationError(
                    f"Chrome {version} cannot be structurally patched: {exc}"
                ) from exc
            print(f"Compatibility: {confidence}")
            for label, position in offsets.items():
                print(f"  {label}: 0x{position:x}")
            print("P4 Seatbelt bypass NOT applied. P6 IOSurface validation bypass applied.")
            if check_only:
                print("[+] Six-patch structural check passed; NO files created.")
                return None

            # Fixed output names: the user can move Google Chrome.app to
            # /Applications directly, without renaming it.
            app_name = "Google Chrome.app"
            shell_name = "launch-chrome-gpu.sh"
            manifest_name = f"chrome-gpu-{version}.patch.json"
            app_output = DOWNLOADS / app_name
            shell_output = DOWNLOADS / shell_name
            manifest_output = DOWNLOADS / manifest_name
            for path in (app_output, shell_output, manifest_output):
                if path.exists() or path.is_symlink():
                    raise PreparationError(
                        f"Output exists; refusing to overwrite: {path}"
                    )
            staged_root.mkdir(parents=True, exist_ok=False)
            print("[*] Cloning and signing isolated test app...")
            command(["/usr/bin/ditto", "--norsrc", str(target), str(stage)])
            _, _, _, _, stage_binary = checked_app(stage)
            if hashlib.sha256(stage_binary.read_bytes()).hexdigest() != digest:
                raise PreparationError("Clone differs from signed DMG")
            strip_codesign_detritus_from_copy(stage)
            # Same successful order as patch_chrome.py: clone, clean
            # metadata, then verify the original Google signature.
            verify_official_google_app(stage)

            # Also authenticate the Chrome 151 donor on a clean private
            # copy.  Verification on the read-only donor DMG itself can
            # fail due to Finder/resource-fork metadata.
            donor_copy = working / "Google Chrome 151 donor.app"
            command(["/usr/bin/ditto", "--norsrc",
                     str(donor), str(donor_copy)])
            _, donor_copy_major, donor_copy_version, donor_copy_fw, _ = checked_app(donor_copy)
            if donor_copy_major != 151 or donor_copy_version != donor_version:
                raise PreparationError("Chrome 151 donor copy changed version")
            strip_codesign_detritus_from_copy(donor_copy)
            verify_official_google_app(donor_copy)

            stage_binary.write_bytes(modified)
            staged_libs = stage_binary.parent / "Libraries"
            staged_libs.mkdir(exist_ok=True)
            for lib in LIBS:
                donor_lib = donor_copy_fw / "Libraries" / lib
                if not donor_lib.is_file():
                    raise PreparationError(f"Missing ANGLE library in DMG: {lib}")
                copy_angle_without_flags(donor_lib, staged_libs / lib)
            sign_test_copy(stage)
            validate_stage(stage, modified, offsets, version)
            signed_framework_hash = hashlib.sha256(stage_binary.read_bytes()).hexdigest()
            del original, modified

            # File publication happens only after all signing and smoke checks.
            # All final outputs live under ~/Downloads, never /Applications.
            shell_tmp = working / shell_name
            shell_tmp.write_text(shell_script(app_name, version, signed_framework_hash),
                                encoding="utf-8")
            shell_tmp.chmod(0o755)
            manifest_tmp = working / manifest_name
            manifest_tmp.write_text(json.dumps({
                "chrome_version": version,
                "source_dmg": str(TARGET_DMG),
                "angle_dmg": str(ANGLE_DMG),
                "source_framework_sha256": digest,
                "signed_framework_sha256": signed_framework_hash,
                "compatibility": confidence,
                "patches": {name: hex(pos) for name, pos in offsets.items()},
                "p4_seatbelt_bypass": False,
                "p6_iosurface_validation_bypass": True,
                "gpu_functional_test_passed": False,
                "user_must_test_before_install": True
            }, indent=2) + "\n", encoding="utf-8")
            for path in (app_output, shell_output, manifest_output):
                if path.exists() or path.is_symlink():
                    raise PreparationError("Output appeared concurrently: " + str(path))
            stage.rename(app_output)
            published.append(app_output)
            shell_tmp.rename(shell_output)
            published.append(shell_output)
            manifest_tmp.rename(manifest_output)
            published.append(manifest_output)
        print(f"\n[+] Prepared: {app_output}")
        print(f"[+] Test launch script: {shell_output}")
        print(f"[+] Patch report: {manifest_output}")
        print(f"Run: {shlex.quote(str(shell_output))}")
        print("Only a live chrome://gpu + visual test can confirm GPU functionality.")
        print("The App is NOT installed or locked; move it yourself after testing.")
        print("Normal Finder launches do NOT inject test flags; use the shell script.")
        return app_output
    except Exception:
        for path in reversed(published):
            if path.is_dir():
                shutil.rmtree(path)
            elif path.exists():
                path.unlink()
        raise
    finally:
        try:
            shutil.rmtree(working)
        except OSError as exc:
            print(f"WARNING: temporary files remain at {working}: {exc}",
                  file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-only", action="store_true",
        help="Read-only scan of both DMGs; do not publish an app or shell script")
    args = parser.parse_args(argv)
    try:
        prepare(check_only=args.check_only)
        return 0
    except (PreparationError, PatchError, GraphicsCompatError,
            SigningError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
