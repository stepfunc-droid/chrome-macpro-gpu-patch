#!/usr/bin/env python3
"""Read-only macOS filesystem-attribute diagnosis for a failed Chrome test copy.

Does not change BSD flags, ACLs, file modes, or extended attributes.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys


def inspect_path(path):
    """Inspect one path WITHOUT following its symlink for ls output."""
    path = Path(path)
    print(f"\n=== {path} ===")
    for command in (
        ["/bin/ls", "-ldeO@", str(path)],
        ["/usr/bin/stat", "-f",
         "owner=%Su group=%Sg permissions=%Sp flags=%Sf", str(path)],
    ):
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        except OSError as exc:
            print(f"  {command[0]} unavailable: {exc}")
            continue
        if result.stdout.strip():
            print(result.stdout.rstrip())
        if result.returncode:
            print(f"  {command[0]} exit={result.returncode}: {result.stderr.strip()}")
    print(f"  can_write={os.access(path, os.W_OK)}")


def inspect_stage(app):
    """Report permissions on the staged versioned Libraries and ANGLE files."""
    app = Path(app).expanduser().absolute()
    if not app.is_dir() or app.name != "Google Chrome.app":
        raise ValueError(f"Expected existing staged Google Chrome.app directory: {app}")
    if not app.parent.name.startswith(".chrome-gl-test-"):
        raise ValueError("Refusing to inspect a non-staging Chrome app; only .chrome-gl-test-*")
    versions = app / "Contents/Frameworks/Google Chrome Framework.framework/Versions"
    # Current is a symlink to the canonical version directory; inspect both.
    current = versions / "Current"
    if current.is_dir():
        version_dir = current
    else:
        # shutil.rmtree() may already have removed the Current symlink
        # before it hit a protected file within the version directory.
        candidates = sorted(p for p in versions.iterdir()
                            if p.is_dir() and not p.is_symlink()
                            and p.name[:1].isdigit())
        if len(candidates) != 1:
            raise ValueError(
                f"Current symlink missing and cannot choose one version "
                f"directory safely: {versions} ({len(candidates)} candidates)"
            )
        version_dir = candidates[0]
        print(f"NOTE: Current symlink is missing after partial cleanup; "
              f"inspecting real directory {version_dir.name}")
    libs = version_dir / "Libraries"
    for path in (
        app.parent,
        versions,
        version_dir,
        libs,
        libs / "libEGL.dylib",
        libs / "libGLESv2.dylib",
    ):
        inspect_path(path)
    print("\nRead-only report. Do not change SIP or system-wide permissions.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True,
                        help="Existing ~/Downloads/.chrome-gl-test-*/Google Chrome.app")
    args = parser.parse_args(argv)
    try:
        inspect_stage(args.stage)
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
