#!/usr/bin/env python3
"""Read-only Chrome 157 P4 instruction diagnostics from original target DMG.

No code modifications, no copied app, no ANGLE donor, no signing. Only a
temporary read-only hdiutil mount which is detached before exit.
"""
import hashlib
import mmap
from pathlib import Path
import sys
import tempfile

from patch_chrome import checked_app, PatchError
from prepare_chrome import TARGET_DMG, mount_dmg, PreparationError
from p4_seatbelt import BUILD_SHA256, BUILD_SIZE, diagnose_p4_patterns


def main():
    if sys.platform != "darwin":
        print("ERROR: Run this diagnostic on macOS.", file=sys.stderr)
        return 1
    if not TARGET_DMG.is_file() or TARGET_DMG.is_symlink():
        print(f"ERROR: Missing original target DMG: {TARGET_DMG}", file=sys.stderr)
        return 1

    try:
        with tempfile.TemporaryDirectory(prefix="chrome-p4-readonly-") as temp:
            with mount_dmg(TARGET_DMG, Path(temp) / "target") as app:
                _, _, version, _, framework_binary = checked_app(app)
                with framework_binary.open("rb") as source:
                    with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                        sha = hashlib.sha256(mapped).hexdigest()
                        print(f"Chrome version: {version}")
                        print(f"Original framework size: {len(mapped)}")
                        print(f"Original framework SHA256: {sha}")
                        if len(mapped) != BUILD_SIZE or sha != BUILD_SHA256:
                            print("WARNING: This is NOT the audited 157 Framework.")
                        print(diagnose_p4_patterns(mapped))
        return 0
    except (PreparationError, PatchError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
