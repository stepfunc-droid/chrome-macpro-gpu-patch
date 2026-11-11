#!/usr/bin/env python3
"""Opt-in P4 Seatbelt check bypass for one audited Chrome M157 framework.

WARNING: skips the conditional error path after the GPU sandbox-state check.
This is a diagnostic-only build, not a sandbox compatibility fix. It does
not remove the OS sandbox, but suppresses a security-state failure check.

Unlike the upstream patcher, do NOT fall back to loose call/test/jump patterns.
Refuse any binary but the exact known Chrome 157 x86_64 framework and any
ambiguous or changed instruction region.
"""
import hashlib
import re

from full_graphics_m157 import BUILD_SHA256, BUILD_SIZE, GraphicsCompatError

P4_NAME = "P4_SeatbeltIsSandboxed_BYPASS"

# Upstream patchers/chrome.py's MOST SPECIFIC M153+ GpuMain context.
# call rel32; test eax,eax; je rel32; mov rdi,[rbx+0x88].
# Never match generic call/test/conditional-jump sequences.
P4_PATTERN = re.compile(
    rb"\x89\xc7\x31\xf6\x31\xd2\x31\xc0\xe8.{4}\x85\xc0"
    rb"(?P<guard>\x0f\x84.{4})"
    rb"\x48\x8b\xbb\x88\x00\x00\x00",
    re.DOTALL,
)


def make_p4_on_control(original, modified, positions, *, version, sha):
    """Return P1-P7 candidate from existing six-patch plan, or fail closed.

    The exact M157 binary digest must match. A unique upstream-anchored P4
    instruction sequence is required; neither C++ symbol names nor offsets
    are assumed. The branch to the GPU sandbox failure path is replaced by
    six NOP bytes. This function never alters the passed-in buffers.
    """
    if (version != "157.0.8103.51" or len(original) != BUILD_SIZE or
            sha != BUILD_SHA256 or hashlib.sha256(original).hexdigest() != BUILD_SHA256):
        raise GraphicsCompatError(
            "P4 experiment requires exact Chrome 157.0.8103.51 x86_64 "
            "original Framework SHA256 and size; newer builds unsupported"
        )
    if len(modified) != len(original):
        raise GraphicsCompatError("P4 original and patched Framework lengths differ")
    required = {
        "allowed_gl_jump", "display_init_jump", "experimental_gl_mode_branch",
        "P5_IOSurfaceFactoryTarget", "P6_IOSurfaceValidateTarget_BYPASS",
        "P7_IOSurfaceBackingTarget",
    }
    if set(positions) != required:
        raise GraphicsCompatError("P4 must be added to the six-patch P1/P2/P3/P5/P6/P7 plan")

    matches = list(P4_PATTERN.finditer(original))
    if len(matches) != 1:
        raise GraphicsCompatError(
            f"P4 GPU Seatbelt check: expected one strictly anchored match; "
            f"found {len(matches)}; refusing unverified bypass"
        )
    offset = matches[0].start("guard")
    end = offset + 6
    expected = original[offset:end]
    if expected[:2] != b"\x0f\x84":
        raise GraphicsCompatError("P4 unexpected branch instruction")
    if modified[offset:end] != expected:
        raise GraphicsCompatError("P4 branch already modified in patch plan")

    # P1-P7 offsets are starts of independently verified regions. P3, P5-P7
    # have more than one modified instruction; compare conservative windows.
    for name, start in positions.items():
        span = 2 if name == "allowed_gl_jump" else 6 if name == "display_init_jump" else 80
        if offset < start + span and start < end:
            raise GraphicsCompatError(f"P4 instruction overlaps existing {name} region")

    data = bytearray(modified)
    data[offset:end] = b"\x90" * 6
    new_positions = dict(positions)
    new_positions[P4_NAME] = offset
    return bytes(data), new_positions
