#!/usr/bin/env python3
"""Chromium M157 full graphics compatibility additions (P5/P6/P7).

The caller applies the existing P1/P2 and exact-build P3 first.
P4 (Seatbelt sandbox-state check bypass) is intentionally NOT included.
P6 changes an IOSurface validation function to unconditional success and
must be treated as an explicitly accepted compatibility/security tradeoff.

Applies only to the 531436704-byte original Chrome 157.0.8103.51 x86_64
framework whose SHA-256 and matching offsets were captured from the user's
read-only local diagnostic. These patterns have NOT been GPU-tested.
"""
import hashlib

BUILD_SHA256 = "81fc51a5952b527f5cd8e9549107effde2f0d4655f75aab75bcfbebae7f6793b"
BUILD_SIZE = 531436704

# These exact offsets / original bytes are taken from the M157 diagnostic.
# The replacements follow the upstream author's patchers/chrome.py P5/P6/P7.
PATCHES = (
    (
        "P5_IOSurfaceFactoryTarget",
        0x1132F4D,
        bytes.fromhex(
            "45 8b 47 38 4c 89 6c 24 18 89 44 24 10 "
            "0f b6 45 cc 89 44 24 08 c7 04 24 01 00 00 00"
        ),
        bytes.fromhex(
            "41 b8 f5 84 00 00 4c 89 6c 24 18 89 44 24 10 "
            "89 04 24 0f b6 45 cc 89 44 24 08 66 90"
        ),
    ),
    (
        "P6_IOSurfaceValidateTarget_BYPASS",
        0xB25F570,
        bytes.fromhex(
            "55 48 89 e5 41 56 53 48 81 ec 30 01 00 00 "
            "81 fe e1 0d 00 00"
        ),
        bytes.fromhex("b0 01 c3") + b"\x90" * 17,
    ),
    (
        "P7_IOSurfaceBackingTarget",
        0xE9A91E,
        bytes.fromhex(
            "8b 45 d0 89 83 90 01 00 00 "
            "8b 45 cc 88 83 94 01 00 00 "
            "45 31 f6 44 89 b3 98 01 00 00 "
            "66 c7 83 9c 01 00 00 00 00"
        ),
        bytes.fromhex(
            "c7 83 90 01 00 00 f5 84 00 00 "
            "8a 45 cc 88 83 94 01 00 00 "
            "45 31 f6 44 89 b3 98 01 00 00 "
            "66 44 89 b3 9c 01 00 00"
        ),
    ),
)

# The upstream launcher auto-adds these. We use the standard Chrome executable
# and explicit CLI flags instead: no launcher replacement or auto-update.
GPU_FLAGS = (
    "--use-angle=gl",
    "--ignore-gpu-blocklist",
    "--disable-features=SkiaGraphite,MediaGmbVideoFramePoolMappableSI",
    "--disable-zero-copy",
    "--ui-disable-zero-copy",
    "--disable-gpu-memory-buffer-compositor-resources",
    "--disable-gpu-memory-buffer-video-frames",
    "--disable-accelerated-video-decode",
    "--disable-accelerated-2d-canvas",
    "--disable-partial-raster",
)


class GraphicsCompatError(Exception):
    pass


def ensure_build(original):
    if len(original) != BUILD_SIZE or hashlib.sha256(original).hexdigest() != BUILD_SHA256:
        raise GraphicsCompatError(
            "Full graphics compatibility requires exact Chrome 157.0.8103.51 "
            f"framework size {BUILD_SIZE}, SHA256 {BUILD_SHA256}; input differs."
        )


def verified_rewrite(original, patched, name, offset, old, new):
    """Apply one instruction-preserving-size edit to a private bytearray.

    Verify original and staged bytes first. Forbid duplicate signatures,
    modified input regions, changed Mach-O size and symlink/OS effects.
    """
    if len(old) != len(new):
        raise GraphicsCompatError(f"{name}: replacement length differs")
    if len(original) != len(patched):
        raise GraphicsCompatError(f"{name}: modified buffer length differs")
    if original[offset:offset + len(old)] != old:
        raise GraphicsCompatError(f"{name}: unexpected M157 bytes at file offset 0x{offset:x}")
    if original.find(old) != offset or original.find(old, offset+1) != -1:
        raise GraphicsCompatError(f"{name}: signature not unique at file offset 0x{offset:x}")
    if patched[offset:offset + len(old)] != old:
        raise GraphicsCompatError(f"{name}: another patch already changed this region")
    patched[offset:offset + len(old)] = new


def apply_graphics_compat_m157(original, previous_patches):
    """Return P1/P2/P3+P5/P6/P7 bytes, fail atomically on any invalid slot.

    Deliberately NEVER modify P4 (GpuMain Seatbelt::IsSandboxed).
    """
    ensure_build(original)
    if len(original) != len(previous_patches):
        raise GraphicsCompatError("Prepared framework length differs from original")
    data = bytearray(previous_patches)
    edits = {}
    for name, offset, old, new in PATCHES:
        verified_rewrite(original, data, name, offset, old, new)
        edits[name] = offset
    return bytes(data), edits
