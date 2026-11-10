#!/usr/bin/env python3
"""Conservative, test-copy-only Chrome ANGLE/OpenGL experiment for Intel Macs.

No system changes, no background service, no sandbox/validation bypass, no
third-party binary downloads, and no modification of the installed Chrome.
This is an experiment: matching patterns does NOT prove GPU compatibility.
"""
import argparse
import hashlib
import os
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile

GL_ALLOWED_ORIG = bytes.fromhex("84 c0 74 0f 80 7d b8 00 74 cd 48 8b 45 b0")
GL_ALLOWED_PATCHED = bytes.fromhex("84 c0 90 90 80 7d b8 00 74 cd 48 8b 45 b0")
GL_ANCHOR = re.compile(
    rb"\x48\x89\xc1\x48\xc1\xe9\x20\x48\x83\xf9\x09.{1,60}"
    rb"\x84\xc0(?P<jump>\x74.)\x80\x7d.\x00", re.DOTALL
)
DISPLAY_PATTERNS = (
    re.compile(rb"\x84\xc0\x0f\x85(?P<disp>.{4})\x48\xb8\x09\x00\x00\x00\x03\x00", re.DOTALL),
    re.compile(rb"\x84\xc0\x0f\x85(?P<disp>.{4})\x83\x7d.\x00\x0f\x85", re.DOTALL),
)
LIBS = ("libEGL.dylib", "libGLESv2.dylib")


class PatchError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def occurrences(haystack, needle):
    out, pos = [], 0
    while True:
        pos = haystack.find(needle, pos)
        if pos == -1:
            return out
        out.append(pos)
        pos += 1


def inspect_binary_patterns(original):
    """Return a bounded, read-only report about unsupported byte patterns.

    These are diagnostic leads, NOT patch targets. In particular, a nearby
    movabs constant is not proof that an instruction belongs to ANGLE setup.
    """
    report = []
    p1_exact = occurrences(original, GL_ALLOWED_ORIG)
    p1_context = list(GL_ANCHOR.finditer(original))
    report.append(f"OpenGL allow check: exact={len(p1_exact)}, anchored={len(p1_context)}")
    for i, pattern in enumerate(DISPLAY_PATTERNS, 1):
        hits = list(pattern.finditer(original))
        report.append(f"Display pattern {i}: {len(hits)} match(es)")
        for hit in hits[:5]:
            report.append(f"  pattern {i} at file offset 0x{hit.start():x}: "
                          f"{original[max(0, hit.start()-16):hit.end()+16].hex(' ')}")
        if len(hits) > 5:
            report.append(f"  ... {len(hits)-5} more match(es) omitted")

    # Search for a compiled constant used by earlier Chromium versions.
    # The M157 compiler may encode this differently or remove it altogether.
    anchors = (
        ("legacy movabs", bytes.fromhex("48 b8 09 00 00 00 03 00")),
        ("legacy stack compare", bytes.fromhex("83 7d 00 00 0f 85")),
    )
    for label, marker in anchors:
        positions = occurrences(original, marker)
        report.append(f"{label}: {len(positions)} occurrence(s)")
        for idx in positions[:8]:
            lo, hi = max(0, idx - 48), min(len(original), idx + len(marker) + 24)
            report.append(f"  file offset 0x{idx:x}, bytes [{lo:x}:{hi:x}]: "
                          f"{original[lo:hi].hex(' ')}")
        if len(positions) > 8:
            report.append(f"  ... {len(positions)-8} more omitted")

    report.append("Offsets are FILE offsets, not virtual addresses. No patch "
                  "candidate is inferred from this report.")
    return report


def plan_binary_patch(original):
    """Return patched bytes and offset report, refusing ambiguous matches."""
    data = bytearray(original)
    positions = occurrences(data, GL_ALLOWED_ORIG)
    if len(positions) == 1:
        p1 = positions[0] + 2
    elif positions:
        raise PatchError("OpenGL check has multiple exact matches; refusing to guess")
    else:
        matches = list(GL_ANCHOR.finditer(data))
        if len(matches) != 1:
            raise PatchError("OpenGL check not unique or absent; unsupported Chrome build")
        p1 = matches[0].start("jump")
    if data[p1:p1 + 2] not in (b"\x74\x0f",) and not (
        data[p1] == 0x74 and len(data[p1:p1 + 2]) == 2
    ):
        raise PatchError("Unexpected OpenGL conditional jump")
    data[p1:p1 + 2] = b"\x90\x90"

    found = [m for pat in DISPLAY_PATTERNS for m in pat.finditer(data)]
    if len(found) != 1:
        raise PatchError("Display initialization check not unique or absent; unsupported Chrome build")
    m = found[0]
    p2 = m.start() + 2
    displacement = struct.unpack("<i", m.group("disp"))[0]
    # JNE rel32 is six bytes; JMP rel32 is five. Preserve the original target.
    data[p2:p2 + 6] = b"\xe9" + struct.pack("<i", displacement + 1) + b"\x90"
    assert len(data) == len(original)
    return bytes(data), {"allowed_gl_jump": p1, "display_init_jump": p2}


def under(path, directory):
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def checked_app(path):
    path = Path(path).expanduser().resolve(strict=True)
    if not path.is_dir() or path.suffix != ".app":
        raise PatchError(f"Not an app bundle: {path}")
    info = path / "Contents/Info.plist"
    with info.open("rb") as f:
        metadata = plistlib.load(f)
    if metadata.get("CFBundleIdentifier") != "com.google.Chrome":
        raise PatchError(f"Not Google Chrome: {path}")
    version = str(metadata.get("CFBundleShortVersionString", ""))
    milestone = int(version.split(".")[0]) if version.split(".")[0].isdigit() else 0
    framework = path / "Contents/Frameworks/Google Chrome Framework.framework/Versions/Current"
    if not framework.is_dir():
        raise PatchError(f"Cannot locate versioned Chrome framework: {path}")
    binary = framework / "Google Chrome Framework"
    if not binary.is_file():
        raise PatchError(f"Cannot locate framework binary: {binary}")
    return path, milestone, version, framework, binary


def cmd(argv):
    result = subprocess.run(argv, text=True, capture_output=True)
    if result.returncode != 0:
        raise PatchError(f"Command failed: {argv[0]} ({result.returncode})\n{result.stderr[-2000:]}")
    return result.stdout


def verify_official_google_app(app):
    """Require a valid app seal AND Google's documented Chrome Team ID."""
    cmd(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)])
    result = subprocess.run(["/usr/bin/codesign", "--display", "--verbose=4", str(app)],
                            text=True, capture_output=True)
    if result.returncode != 0 or "TeamIdentifier=EQHXZ8M8AV" not in (result.stdout + result.stderr):
        raise PatchError(f"Not signed by the official Google Chrome Team ID: {app}")


def preflight(source, angle, output, experimental):
    source, major, version, _, binary = checked_app(source)
    angle, angle_major, angle_version, angle_fw, _ = checked_app(angle)
    home = Path.home().resolve()
    output = Path(output).expanduser().resolve(strict=False)
    if not str(output).endswith(".app"):
        raise PatchError("Output must end with .app")
    if output.exists() or output.is_symlink():
        raise PatchError(f"Output already exists: {output}")
    if not under(output, home) or not output.parent.is_dir():
        raise PatchError("Output must be a new .app path inside an existing directory under your home")
    if output == source or output == angle or under(output, source) or under(output, angle):
        raise PatchError("Output cannot overlap an input")
    if major < 152:
        raise PatchError(f"Target Chrome {version} is older than the M152 GL removal")
    if major not in (152, 153) and not experimental:
        raise PatchError(f"Chrome M{major} is UNTESTED; explicitly use --experimental-version")
    if angle_major > 151:
        raise PatchError("ANGLE donor must be original Chrome 151 or older")
    lib_paths = []
    for name in LIBS:
        p = angle_fw / "Libraries" / name
        if not p.is_file():
            raise PatchError(f"Donor Chrome {angle_version} is missing {p}")
        lib_paths.append(p)
    original = binary.read_bytes()
    modified, report = plan_binary_patch(original)
    if modified == original:
        raise PatchError("No binary modification produced")
    return source, version, output, original, modified, report, lib_paths


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Clean, latest official Google Chrome.app")
    parser.add_argument("--diagnose", action="store_true", help="Read-only pattern report; needs only --source")
    parser.add_argument("--angle-from", help="Clean Google Chrome 151.app with ANGLE libraries")
    parser.add_argument("--output", help="NEW test copy, under your home (must not exist)")
    parser.add_argument("--experimental-version", action="store_true",
                        help="Allow unvalidated milestone (e.g. M157), if byte signatures match exactly")
    parser.add_argument("--apply", action="store_true", help="Actually create and re-sign the test copy")
    args = parser.parse_args(argv)

    try:
        if args.diagnose:
            if args.apply:
                raise PatchError("--diagnose cannot be combined with --apply")
            source, major, version, _, binary = checked_app(args.source)
            original = binary.read_bytes()
            print(f"Read-only diagnostic: Chrome {version} (M{major})")
            print(f"Input binary: {binary}")
            print(f"Size: {len(original)} bytes; SHA256: {sha256(original)}")
            for line in inspect_binary_patterns(original):
                print(line)
            return 0
        if not args.angle_from or not args.output:
            raise PatchError("--angle-from and --output are required unless --diagnose is used")
        if args.apply and sys.platform != "darwin":
            raise PatchError("Applying requires macOS; pattern analysis works on other systems")
        if args.apply and os.geteuid() == 0:
            raise PatchError("Do not run this script as root or with sudo")
        source, version, output, original, modified, report, libs = preflight(
            args.source, args.angle_from, args.output, args.experimental_version)
        print(f"Chrome version: {version}; input SHA256: {sha256(original)}")
        for name, offset in report.items():
            print(f"  {name}: 0x{offset:x}")
        print("ANGLE donor files:", ", ".join(str(p) for p in libs))
        print("Unchanged: GPU sandbox, IOSurface validation, GPU fallback mode, launcher.")
        print("No automatic updates, no downloaded libraries, no existing app modification.")
        if not args.apply:
            print("DRY RUN ONLY; pass --apply to create the test copy.")
            return 0

        # Fail if source has a bad signature. Donor app must also be intact.
        for app in (source, Path(args.angle_from).expanduser().resolve(strict=True)):
            verify_official_google_app(app)
        workdir = Path(tempfile.mkdtemp(prefix=".chrome-gl-test-", dir=str(output.parent)))
        stage = workdir / "Google Chrome.app"
        try:
            cmd(["/usr/bin/ditto", str(source), str(stage)])
            _, copied_major, _, copied_fw, copied_binary = checked_app(stage)
            if sha256(copied_binary.read_bytes()) != sha256(original):
                raise PatchError("Clone did not match original; aborting")
            copied_binary.write_bytes(modified)
            dest_libdir = copied_fw / "Libraries"
            dest_libdir.mkdir(parents=True, exist_ok=True)
            for donor in libs:
                shutil.copy2(donor, dest_libdir / donor.name)
            # Ad-hoc signing changes the browser identity. Preserve helper entitlements.
            cmd(["/usr/bin/codesign", "--force", "--deep", "--sign", "-",
                 "--preserve-metadata=entitlements,flags", str(stage)])
            cmd(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(stage)])
            if output.exists() or output.is_symlink():
                raise PatchError("Output appeared while patching; refusing overwrite")
            stage.rename(output)
        finally:
            shutil.rmtree(workdir)
        print(f"Created: {output}")
        exe = output / "Contents/MacOS/Google Chrome"
        profile = output.parent / "Chrome-GPU-Test-Profile"
        print("Test with a disposable profile (do NOT log in to important accounts):")
        print(f'  "{exe}" --user-data-dir="{profile}" --use-angle=gl --ignore-gpu-blocklist --no-first-run')
        print("Check chrome://gpu. A successful signature does NOT prove GPU acceleration.")
        print("To uninstall, close the test browser and delete only the test .app and profile.")
        return 0
    except (PatchError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
