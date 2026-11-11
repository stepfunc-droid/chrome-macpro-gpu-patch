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
import stat
import struct
import subprocess
import sys
import tempfile
import traceback

from signing import sign_test_copy, SigningError
from full_graphics_m157 import (
    apply_graphics_compat_m157, GraphicsCompatError, GPU_FLAGS, PATCHES
)

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
# Exact Google Chrome 157.0.8103.51 x86_64 binary reported from the MacBook
# Pro 11,3 test machine. This is not a general M157/M158 patch signature.
M157_AUDITED_SHA256 = "81fc51a5952b527f5cd8e9549107effde2f0d4655f75aab75bcfbebae7f6793b"
M157_P3_OFFSET = 0x1FA5846
M157_P3_ORIGINAL = bytes.fromhex(
    "84 c0 0f 84 9b 00 00 00 4c 89 ff e8 ca d5 01 01"
    "c7 45 ac 03 00 00 00 48 8b 83 40 07 00 00"
)
M157_P3_BRANCH_OFFSET = 2
M157_P3_ENUM_OFFSET = 19



class PatchError(Exception):
    pass


def copy_angle_without_flags(source, destination):
    """Copy ANGLE data and Unix mode, but never donor BSD flags or xattrs.

    shutil.copy2() invokes copystat(), which can carry macOS's uchg flag
    over from the Google-signed donor. That prevents codesign --force and
    even temporary-directory cleanup (EPERM). Use copyfile instead.
    """
    destination = Path(destination)
    if destination.is_symlink():
        raise PatchError(f"Refusing to overwrite a symlinked ANGLE destination: {destination}")
    shutil.copyfile(source, destination)
    destination.chmod(stat.S_IMODE(Path(source).stat().st_mode))
    flags = getattr(destination.stat(), "st_flags", 0)
    immutable = getattr(stat, "UF_IMMUTABLE", 0)
    if immutable and (flags & immutable):
        raise PatchError(f"Staged ANGLE library unexpectedly has uchg: {destination}")
    return destination


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

    # Read-only upstream-patch reconnaissance for M157. These patterns were
    # authored around M152/M153 and MUST NOT be applied without checking
    # the control-flow of the exact M157 binary. GpuMode=3 in M157 denotes
    # HARDWARE_GRAPHITE, not DISABLED, despite upstream patch 3's description.
    upstream_signatures = (
        ("P3 GPU mode (conditional + write 3)", re.compile(
            rb"\x84\xc0(?:\x0f\x84.{4}|\x74.)(?:.{0,16})"
            rb"\xc7\x45.\x03\x00\x00\x00\x48\x8b\x83", re.DOTALL)),
        ("P5 IOSurface factory", re.compile(
            rb"\x45\x8b\x47\x38\x4c\x89\x6c\x24\x18"
            rb"\x89\x44\x24\x10\x0f\xb6\x45."
            rb"\x89\x44\x24\x08\xc7\x04\x24\x01\x00\x00\x00",
            re.DOTALL)),
        ("P6 IOSurface target validate", re.compile(
            rb"\x55\x48\x89\xe5(?:\x41[\x50-\x57]|[\x50-\x57]){1,4}"
            rb"\x48\x81\xec\x30\x01\x00\x00\x81\xfe\xe1\x0d\x00\x00",
            re.DOTALL)),
        ("P7 IOSurface backing target", re.compile(
            rb"\x8b\x45.\x89\x83..\x00\x00\x8b\x45."
            rb"\x88\x83..\x00\x00\x45\x31\xf6"
            rb"\x44\x89\xb3..\x00\x00"
            rb"\x66\xc7\x83..\x00\x00\x00\x00",
            re.DOTALL)),
    )
    report.append("Upstream P3/P5/P6/P7 signature audit (READ-ONLY, M157 UNVALIDATED):")
    for label, pattern in upstream_signatures:
        hits = list(pattern.finditer(original))
        report.append(f"  {label}: {len(hits)} candidate(s)")
        for hit in hits[:3]:
            lo = max(0, hit.start() - 24)
            hi = min(len(original), hit.end() + 24)
            report.append(
                f"    file offset 0x{hit.start():x}, context "
                f"[{lo:x}:{hi:x}]: {original[lo:hi].hex(' ')}"
            )
        if len(hits) > 3:
            report.append(f"    ... {len(hits) - 3} further matches omitted")
    report.append("P4 Seatbelt bypass intentionally omitted from audit targets.")
    report.append("Neither a unique byte pattern nor a numeric enum constant "
                  "proves a function or a safe patch target.")

    report.append("Offsets are FILE offsets, not virtual addresses. No patch "
                  "candidate is inferred from this report.")
    return report


def patch_gpu_mode_branch_m157(data, offset):
    """Experimental GPU mode candidate: bypass Graphite gate, write GL enum.

    M157 enum value 3 is HARDWARE_GRAPHITE, not DISABLED. The original
    branch guards adding a Graphite candidate. Bypassing that *specific*
    conditional and changing the pushed enum to 1 (HARDWARE_GL) is a
    hypothesis for restoring the GL candidate, not a proven GPU fix.
    It does not disable Chromium's fallback or alter sandbox/IOSurface code.
    """
    if data[offset:offset + len(M157_P3_ORIGINAL)] != M157_P3_ORIGINAL:
        raise PatchError("M157 GPU mode instructions differ from audited bytes")
    data[offset + M157_P3_BRANCH_OFFSET:
         offset + M157_P3_BRANCH_OFFSET + 6] = b"\x90" * 6
    data[offset + M157_P3_ENUM_OFFSET] = 1


def apply_gpu_mode_experiment_m157(original, patched):
    """Fail closed unless the *entire input binary* is the audited M157 build."""
    if len(original) != 531436704 or sha256(original) != M157_AUDITED_SHA256:
        raise PatchError(
            "GPU mode experiment is only supported on exact audited "
            "Chrome 157.0.8103.51 binary SHA256 "
            + M157_AUDITED_SHA256
        )
    hits = occurrences(original, M157_P3_ORIGINAL)
    if hits != [M157_P3_OFFSET]:
        raise PatchError(
            f"GPU mode bytes not unique at audited file offset; found: {hits[:5]}"
        )
    patch_gpu_mode_branch_m157(patched, M157_P3_OFFSET)
    return M157_P3_OFFSET


def plan_binary_patch(original, *, gpu_mode_experiment=False, full_graphics_compat=False):
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

    # These are alternatives, NOT two independent targets. On Chromium M157,
    # the specific ANGLE movabs pattern and the broader legacy stack-compare
    # pattern each match once in *different* functions. Summing both causes a
    # false "ambiguous" error. Prefer the more contextual movabs signature.
    primary = list(DISPLAY_PATTERNS[0].finditer(data))
    if len(primary) > 1:
        raise PatchError("Specific ANGLE display check has multiple matches; refusing to guess")
    if primary:
        m = primary[0]
    else:
        fallback = list(DISPLAY_PATTERNS[1].finditer(data))
        if len(fallback) != 1:
            raise PatchError(
                "Specific ANGLE display check absent and legacy fallback is "
                "not unique; unsupported Chrome build"
            )
        m = fallback[0]
    p2 = m.start() + 2
    displacement = struct.unpack("<i", m.group("disp"))[0]
    # JNE rel32 is six bytes; JMP rel32 is five. Preserve the original target.
    data[p2:p2 + 6] = b"\xe9" + struct.pack("<i", displacement + 1) + b"\x90"
    report = {"allowed_gl_jump": p1, "display_init_jump": p2}
    if gpu_mode_experiment or full_graphics_compat:
        report["experimental_gl_mode_branch"] = apply_gpu_mode_experiment_m157(
            original, data)
    if full_graphics_compat:
        # P4 is NOT applied: this is P1/P2/P3 + P5/P6/P7, with an
        # explicit IOSurface validation bypass (P6). All-or-nothing.
        combined, extra = apply_graphics_compat_m157(original, data)
        report.update(extra)
        data = bytearray(combined)
    assert len(data) == len(original)
    return bytes(data), report


def verify_full_graphics_output(app_path):
    """Read-only on-disk verification for M157 graphics experiment.

    This does not assert that an already-running GPU Helper loaded the
    verified framework. That must be checked using ps/lsof on the Mac.
    """
    app, major, version, _, binary = checked_app(app_path)
    if version != "157.0.8103.51":
        raise PatchError(f"Expected Chrome 157.0.8103.51, found {version}")
    data = binary.read_bytes()
    # A locally re-signed Mach-O may have a different LC_CODE_SIGNATURE
    # blob length than the Google-signed original. The original input
    # length/hash precondition belongs ONLY to the pre-patch preflight;
    # verify a generated copy by specific modified instructions instead.
    # Reject truncated binaries where the last known patch span is missing.
    last_patch_end = max(offset + len(new) for _, offset, _, new in PATCHES)
    if len(data) < last_patch_end:
        raise PatchError(
            f"Framework truncated before known patch regions: size={len(data)}"
        )
    p1 = occurrences(data, GL_ALLOWED_PATCHED)
    p2 = list(re.finditer(
        rb"\x84\xc0\xe9.{4}\x90\x48\xb8\x09\x00\x00\x00\x03\x00",
        data, re.DOTALL))
    expected_p3 = bytearray(M157_P3_ORIGINAL)
    patch_gpu_mode_branch_m157(expected_p3, 0)
    tests = [
        ("P1 ANGLE allowlist", len(p1) == 1,
         f"matches={len(p1)}"),
        ("P2 EGL initialization", len(p2) == 1 and p2[0].start() == 0x3520FF7,
         f"matches={len(p2)}"),
        ("P3 HARDWARE_GL mode", data[M157_P3_OFFSET:M157_P3_OFFSET + len(expected_p3)]
         == bytes(expected_p3), f"offset=0x{M157_P3_OFFSET:x}"),
    ]
    for name, offset, old, new in PATCHES:
        tests.append((name,
                      data[offset:offset + len(new)] == new,
                      f"offset=0x{offset:x}"))
    print(f"Read-only verification of {app}")
    print(f"Framework size (re-signed): {len(data)} bytes")
    print(f"Framework SHA256 (patched): {sha256(data)}")
    for name, ok, detail in tests:
        print(f"  {'OK' if ok else 'FAIL'}  {name}: {detail}")
    if not all(ok for _, ok, _ in tests):
        raise PatchError("Full graphics patch is absent or incomplete")
    print("All six graphics patch regions verified ON DISK.")
    print("This does NOT prove the running GPU Helper loaded this binary.")
    print("To check running test processes:")
    print("  ps -axo pid,ppid,command | grep -F 'Chrome GPU Test v' | grep -v grep")


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


def strip_codesign_detritus_from_copy(app):
    """Remove only Finder/resource-fork metadata from the temporary app copy.

    macOS Python builds do not necessarily provide os.listxattr/removexattr.
    Use the system xattr utility instead. Never follow symlinks or modify the
    source installation; preserve all other extended attributes.
    """
    removed = 0
    names = {"com.apple.FinderInfo", "com.apple.ResourceFork"}
    for root, dirs, files in os.walk(app, followlinks=False):
        for item in (root, *(os.path.join(root, name) for name in dirs + files)):
            if os.path.islink(item):
                continue
            # On macOS, 'xattr /path' prints one attribute name per line.
            present = set(cmd(["/usr/bin/xattr", str(item)]).splitlines())
            for attr in sorted(present & names):
                cmd(["/usr/bin/xattr", "-d", attr, str(item)])
                removed += 1
    return removed


def verify_official_google_app(app):
    """Require a valid app seal AND Google's documented Chrome Team ID."""
    cmd(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)])
    result = subprocess.run(["/usr/bin/codesign", "--display", "--verbose=4", str(app)],
                            text=True, capture_output=True)
    if result.returncode != 0 or "TeamIdentifier=EQHXZ8M8AV" not in (result.stdout + result.stderr):
        raise PatchError(f"Not signed by the official Google Chrome Team ID: {app}")


def preflight(source, angle, output, experimental, gpu_mode_experiment=False,
              full_graphics_compat=False):
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
    modified, report = plan_binary_patch(
        original, gpu_mode_experiment=gpu_mode_experiment,
        full_graphics_compat=full_graphics_compat)
    if modified == original:
        raise PatchError("No binary modification produced")
    return source, version, output, original, modified, report, lib_paths


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Clean, latest official Google Chrome.app")
    parser.add_argument("--diagnose", action="store_true", help="Read-only pattern report; needs only --source")
    parser.add_argument("--verify-full-graphics", action="store_true",
                        help="Read-only on-disk verification of P1/P2/P3/P5/P6/P7 "
                             "on --source test app (never writes)")
    parser.add_argument("--angle-from", help="Clean Google Chrome 151.app with ANGLE libraries")
    parser.add_argument("--output", default="~/Downloads/Chrome GPU Test.app",
                        help="NEW test copy, under your home (default: ~/Downloads/Chrome GPU Test.app)")
    parser.add_argument("--experimental-version", action="store_true",
                        help="Allow unvalidated milestone (e.g. M157), if byte signatures match exactly")
    parser.add_argument("--experimental-gpu-mode", action="store_true",
                        help="M157 exact-SHA experiment: permit HARDWARE_GL fallback candidate "
                             "(does NOT bypass Sandbox, IOSurface checks or crash fallback)")
    parser.add_argument("--full-graphics-compat", action="store_true",
                        help="Exact-M157 P1/P2/P3/P5/P6/P7 experiment, no P4 sandbox "
                             "bypass (P6 skips IOSurface target validation)")
    parser.add_argument("--inject-launcher", action="store_true",
                        help="Compile the repo's native flag-injecting Chrome launcher "
                             "IN THE TEST COPY before signing (only --full-graphics-compat)")
    parser.add_argument("--apply", action="store_true", help="Actually create and re-sign the test copy")
    parser.add_argument("--debug", action="store_true", help="Show full traceback if staged-copy operations fail")
    args = parser.parse_args(argv)
    phase = "preflight"

    try:
        if args.verify_full_graphics:
            if args.apply or args.diagnose:
                raise PatchError("--verify-full-graphics is read-only; "
                                 "cannot combine with --apply or --diagnose")
            verify_full_graphics_output(args.source)
            return 0
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
        if args.inject_launcher and not args.full_graphics_compat:
            raise PatchError("--inject-launcher requires --full-graphics-compat")
        if args.experimental_gpu_mode and args.full_graphics_compat:
            raise PatchError("Choose either --experimental-gpu-mode or "
                             "--full-graphics-compat, not both")
        if (args.experimental_gpu_mode or args.full_graphics_compat) and not args.experimental_version:
            raise PatchError("Experimental GPU modes require --experimental-version")
        if not args.angle_from:
            raise PatchError("--angle-from is required unless --diagnose is used")
        if args.apply and sys.platform != "darwin":
            raise PatchError("Applying requires macOS; pattern analysis works on other systems")
        if args.apply and os.geteuid() == 0:
            raise PatchError("Do not run this script as root or with sudo")
        source, version, output, original, modified, report, libs = preflight(
            args.source, args.angle_from, args.output, args.experimental_version,
            args.experimental_gpu_mode, args.full_graphics_compat)
        print(f"Chrome version: {version}; input SHA256: {sha256(original)}")
        for name, offset in report.items():
            print(f"  {name}: 0x{offset:x}")
        print("ANGLE donor files:", ", ".join(str(p) for p in libs))
        if args.full_graphics_compat:
            print("FULL GRAPHICS EXPERIMENT: P1/P2/P3/P5/P6/P7. "
                  "P4 Seatbelt bypass is EXCLUDED.")
            print("WARNING: P6 bypasses IOSurface texture target validation. "
                  "Do not use this test browser for sensitive accounts.")
            print("Unchanged: GPU sandbox/Seatbelt checks, crash fallback, launcher.")
        elif args.experimental_gpu_mode:
            print("EXPERIMENT: Adds a HARDWARE_GL candidate in Chromium GPU mode "
                  "selection for this exact M157 build.")
            print("Unchanged: GPU sandbox, IOSurface validation, mode fallback, launcher.")
        else:
            print("Unchanged: GPU sandbox, IOSurface validation, GPU mode, launcher.")
        print("No automatic updates, no downloaded libraries, no existing app modification.")
        if not args.apply:
            print("DRY RUN ONLY; pass --apply to create the test copy.")
            return 0

        # Verify the Chrome 151 ANGLE donor without changing its installed app.
        phase = "verify donor Chrome 151 signature"
        verify_official_google_app(Path(args.angle_from).expanduser().resolve(strict=True))
        workdir = Path(tempfile.mkdtemp(prefix=".chrome-gl-test-", dir=str(output.parent)))
        stage = workdir / "Google Chrome.app"
        try:
            # --norsrc skips HFS resource forks and Finder metadata while
            # preserving the actual executable and signed bundle resources.
            phase = "clone Chrome 157 into staging"
            cmd(["/usr/bin/ditto", "--norsrc", str(source), str(stage)])
            _, copied_major, _, copied_fw, copied_binary = checked_app(stage)
            if sha256(copied_binary.read_bytes()) != sha256(original):
                raise PatchError("Clone did not match original; aborting")
            phase = "remove unsupported staged metadata"
            count = strip_codesign_detritus_from_copy(stage)
            print(f"[*] Removed {count} prohibited Finder/resource-fork attributes from test copy.")
            # Verify ORIGINAL Google-signed content in the CLEANED COPY.
            # A damaged vendor signature must still fail, not be ignored.
            phase = "verify staged Google signature"
            verify_official_google_app(stage)
            phase = "write validated framework byte patches"
            copied_binary.write_bytes(modified)
            dest_libdir = copied_fw / "Libraries"
            phase = "check staged Libraries directory"
            if not dest_libdir.is_dir():
                dest_libdir.mkdir(parents=True, exist_ok=True)
            for donor in libs:
                phase = f"copy ANGLE library {donor.name} without BSD flags"
                copy_angle_without_flags(donor, dest_libdir / donor.name)
            if args.inject_launcher:
                # Compile the upstream-style launcher into the isolated staging
                # app, then sign it as part of the final app. It injects only
                # GPU_FLAGS, not --no-sandbox, and does not install any service.
                phase = "compile native GPU-flag launcher in staged app"
                launcher_src = Path(__file__).resolve().parent.parent / "chrome_main.c"
                if not launcher_src.is_file():
                    raise PatchError(f"Launcher source missing: {launcher_src}")
                launcher_dst = stage / "Contents/MacOS/Google Chrome"
                if not launcher_dst.is_file() or launcher_dst.is_symlink():
                    raise PatchError("Unexpected launcher destination")
                launcher_new = launcher_dst.with_name("Google Chrome.new")
                cmd(["/usr/bin/clang", "-O2", "-Wall", "-Wextra",
                     str(launcher_src), "-o", str(launcher_new)])
                # Atomic replacement, not in-place mutation of a vendor
                # binary that may carry immutable flags.
                os.replace(launcher_new, launcher_dst)
            # Ad-hoc signing changes the browser identity. Never preserve
            # Google-only Team ID/keychain entitlements in locally signed code.
            # Sign library/framework/helper/outer app separately per Chromium.
            phase = "sign staged Chrome components"
            print("[*] Signing staged Chrome components...", flush=True)
            sign_test_copy(stage)
            if output.exists() or output.is_symlink():
                raise PatchError("Output appeared while patching; refusing overwrite")
            phase = "publish staged Chrome test copy"
            stage.rename(output)
        finally:
            # Cleanup errors must NEVER mask the original patch/signing error.
            # Chrome bundles can carry immutable flags or restrictive ACLs.
            try:
                shutil.rmtree(workdir)
            except OSError as cleanup_exc:
                print(f"[!] Could not fully remove staging directory {workdir}: "
                      f"{cleanup_exc}", file=sys.stderr)
                print("[!] Staged files remain; inspect that exact directory "
                      "before deleting it manually (never use sudo blindly).", file=sys.stderr)
        print(f"Created: {output}")
        exe = output / "Contents/MacOS/Google Chrome"
        profile = output.parent / (
            "Chrome-GPU-Full-Compat-Profile" if args.full_graphics_compat else
            "Chrome-GPU-Mode-Profile" if args.experimental_gpu_mode else
            "Chrome-GPU-Test-Profile"
        )
        print("Test with a disposable profile (do NOT log in to important accounts):")
        if args.full_graphics_compat:
            flags = " \\\n    ".join(GPU_FLAGS)
            print(f'  "{exe}" --user-data-dir="{profile}" \\\n    {flags} \\\n    --no-first-run')
        else:
            print(f'  "{exe}" --user-data-dir="{profile}" --use-angle=gl --ignore-gpu-blocklist --no-first-run')
        print("Check chrome://gpu. A successful signature does NOT prove GPU acceleration.")
        print("To uninstall, close the test browser and delete only the test .app and profile.")
        return 0
    except (PatchError, SigningError, GraphicsCompatError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"ERROR in phase [{phase}]: {type(exc).__name__}: {exc}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
