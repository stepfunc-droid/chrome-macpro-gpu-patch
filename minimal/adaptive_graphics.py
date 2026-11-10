#!/usr/bin/env python3
"""Fail-closed compatibility scan for new Chrome builds.

Exact M157 hash uses the already hardware-tested patch. Other versions are
considered *structurally patchable* only when every unique anchored machine
code signature matches. This does NOT establish GPU runtime compatibility.

P1/P2/P3/P5/P6/P7 only: deliberately NEVER patches P4 Seatbelt check.
P6 unconditionally skips IOSurface target validation (compatibility risk).
"""
import re

from patch_chrome import PatchError, plan_binary_patch
from full_graphics_m157 import BUILD_SHA256, BUILD_SIZE, GraphicsCompatError
from full_graphics_m157 import PATCHES as M157_PATCHES

P3 = re.compile(
    rb"\x84\xc0(?P<guard>\x0f\x84.{4})"
    rb"(?P<gap>.{0,16})\xc7\x45.(?P<mode>\x03)\x00\x00\x00"
    rb"\x48\x8b\x83", re.DOTALL
)
P5 = re.compile(
    rb"\x45\x8b\x47\x38\x4c\x89\x6c\x24\x18\x89\x44\x24\x10"
    rb"\x0f\xb6\x45(?P<reg>.)\x89\x44\x24\x08"
    rb"\xc7\x04\x24\x01\x00\x00\x00", re.DOTALL
)
P6 = re.compile(
    rb"\x55\x48\x89\xe5(?:\x41[\x50-\x57]|[\x50-\x57]){1,4}"
    rb"\x48\x81\xec\x30\x01\x00\x00\x81\xfe\xe1\x0d\x00\x00",
    re.DOTALL
)
P7 = re.compile(
    rb"\x8b\x45.(?P<write>\x89\x83(?P<target>..\x00\x00))"
    rb"\x8b\x45(?P<reg>.)\x88\x83(?P<other>..\x00\x00)"
    rb"\x45\x31\xf6\x44\x89\xb3(?P<zero>..\x00\x00)"
    rb"\x66\xc7\x83(?P<short>..\x00\x00)\x00\x00",
    re.DOTALL
)
P6_REPLACEMENT = bytes.fromhex("b0 01 c3") + b"\x90" * 17


def unique(data, regex, label):
    matches = list(regex.finditer(data))
    if len(matches) != 1:
        raise GraphicsCompatError(
            f"{label}: expected exactly one anchored instruction match; found {len(matches)}"
        )
    return matches[0]


def scan_and_patch(original, *, version, sha):
    """Return modified bytes, verified offsets, and confidence category.

    For unrecognized hashes, only *structural* compatibility is established.
    The caller must produce a test app, not install an untested browser.
    """
    if not version or not version.split(".")[0].isdigit():
        raise GraphicsCompatError("Cannot determine a Chrome milestone")
    if int(version.split(".")[0]) < 152:
        raise GraphicsCompatError("Chrome is older than M152; unsupported")
    is_known = len(original) == BUILD_SIZE and sha == BUILD_SHA256
    if is_known:
        modified, positions = plan_binary_patch(original, full_graphics_compat=True)
        return modified, positions, "M157_HARDWARE_TESTED"

    # Reuse existing guarded P1/P2 and adapt P3/P5/P6/P7 by unique
    # machine-code context, never by M157 absolute offsets.
    modified, positions = plan_binary_patch(original)
    data = bytearray(modified)

    match = unique(original, P3, "P3 GPU mode")
    # A 6-byte conditional jump, branch opcode 0F 84, and the immediate
    # value 3 all have to be present in one unique instruction context.
    a = match.start("guard")
    data[a:a + 6] = b"\x90" * 6
    data[match.start("mode")] = 1
    positions["experimental_gl_mode_branch"] = match.start()

    match = unique(original, P5, "P5 IOSurface factory target")
    reg = match.group("reg")
    replacement = (bytes.fromhex(
        "41 b8 f5 84 00 00 4c 89 6c 24 18 89 44 24 10"
        "89 04 24 0f b6 45"
    ) + reg + bytes.fromhex("89 44 24 08 66 90"))
    if len(replacement) != len(match.group()):
        raise GraphicsCompatError("P5 replacement size changed")
    data[match.start():match.end()] = replacement
    positions["P5_IOSurfaceFactoryTarget"] = match.start()

    match = unique(original, P6, "P6 IOSurface target validation")
    # The upstream P6 prologue must begin with the exact known 20-byte
    # sequence; our patch short-circuits this function entirely.
    target = match.start()
    if original[target:target + 20] != bytes.fromhex(
        "55 48 89 e5 41 56 53 48 81 ec 30 01 00 00 81 fe e1 0d 00 00"
    ):
        raise GraphicsCompatError("P6 unexpected function prologue; refusing bypass")
    data[target:target + 20] = P6_REPLACEMENT
    positions["P6_IOSurfaceValidateTarget_BYPASS"] = target

    match = unique(original, P7, "P7 IOSurface backing target")
    # All target fields come from the captured instruction, not M157 offsets.
    replacement = (
        bytes.fromhex("c7 83") + match.group("target") +
        bytes.fromhex("f5 84 00 00 8a 45") + match.group("reg") +
        bytes.fromhex("88 83") + match.group("other") +
        bytes.fromhex("45 31 f6 44 89 b3") + match.group("zero") +
        bytes.fromhex("66 44 89 b3") + match.group("short")
    )
    if len(replacement) != len(match.group()):
        raise GraphicsCompatError("P7 replacement size changed")
    data[match.start():match.end()] = replacement
    positions["P7_IOSurfaceBackingTarget"] = match.start()

    if len(data) != len(original):
        raise GraphicsCompatError("Patched binary length changed")
    return bytes(data), positions, "STRUCTURAL_ONLY_UNTESTED"


def verify_patched_regions(original, staged, *, version, sha):
    """Require every intended modified byte region to survive code signing.

    Codesign may resize the signature blob, so original and re-signed binary
    lengths are *not* compared; only intended code bytes are checked.
    """
    modified, positions, level = scan_and_patch(
        original, version=version, sha=sha
    )
    if len(staged) < len(modified) - 4096:
        raise GraphicsCompatError("Signed framework unexpectedly truncated")
    # Validate every byte change; Apple codesign should only affect the
    # signature, not the instructions we patched.
    changes = [i for i, (a, b) in enumerate(zip(original, modified)) if a != b]
    if not changes:
        raise GraphicsCompatError("No patch changes identified")
    for idx in changes:
        if staged[idx] != modified[idx]:
            raise GraphicsCompatError(
                f"Signed candidate lost patch at file offset 0x{idx:x}"
            )
    if len(positions) != 6:
        raise GraphicsCompatError(
            f"Expected six patch regions, got {list(positions)}"
        )
    return positions, level
