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

# Bytes reported by read-only diagnose_p4.py on the audited Chrome
# 157.0.8103.51 x86_64 Framework. No absolute address inferred from a
# different Chrome build is used.
#
# Upstream's P4 site uses the sequence:
#   mov edi,eax; xor esi,esi; xor edx,edx; xor eax,eax
#   call rel32; test eax,eax; je near; mov rdi,[rbx+0x88]
# In this M157 binary the corresponding candidate differs in the final
# displacement: [rbx+0x90]. The exact CALL and JE displacements below
# are from the user's diagnostic; function identity is not proven by these
# bytes alone. Treat this as an experimental, explicit security-check bypass.
P4_M157_CONTEXT_OFFSET = 0x1E1400A
P4_M157_CONTEXT = bytes.fromhex(
    "89 c7 31 f6 31 d2 31 c0 "
    "e8 ad 2f 42 0c 85 c0 "
    "0f 84 f7 00 00 00 "
    "48 8b bb 90 00 00 00"
)
P4_M157_GUARD_OFFSET = P4_M157_CONTEXT_OFFSET + 15
P4_M157_GUARD_ORIGINAL = bytes.fromhex("0f 84 f7 00 00 00")
P4_M157_GUARD_PATCHED = b"\x90" * 6

# Upstream patchers/chrome.py's MOST SPECIFIC M153+ GpuMain context.
# call rel32; test eax,eax; je rel32; mov rdi,[rbx+0x88].
# Never match generic call/test/conditional-jump sequences.
P4_PATTERN = re.compile(
    rb"\x89\xc7\x31\xf6\x31\xd2\x31\xc0\xe8.{4}\x85\xc0"
    rb"(?P<guard>\x0f\x84.{4})"
    rb"\x48\x8b\xbb\x88\x00\x00\x00",
    re.DOTALL,
)



# Read-only, progressively looser evidence probes. These are *never* used
# to select a patch offset; they exist only to inspect compiler variation.
# In particular, CALL/TEST/Jcc can appear thousands of times in Chrome.
P4_DIAGNOSTIC_PATTERNS = (
    ("strict upstream M153+ context", P4_PATTERN),
    ("observed Chrome 157 exact [rbx+0x90] context", re.compile(re.escape(P4_M157_CONTEXT))),
    ("upstream GpuMain prefix through CALL/TEST", re.compile(
        rb"\x89\xc7\x31\xf6\x31\xd2\x31\xc0\xe8.{4}\x85\xc0",
        re.DOTALL,
    )),
    ("TEST/JE-near followed by RBX+0x88 load", re.compile(
        rb"\x85\xc0\x0f\x84.{4}\x48\x8b\xbb\x88\x00\x00\x00",
        re.DOTALL,
    )),
    ("TEST/JE-short followed by RBX+0x88 load", re.compile(
        rb"\x85\xc0\x74.\x48\x8b\xbb\x88\x00\x00\x00",
        re.DOTALL,
    )),
    ("CALL/TEST/JE-near (generic; NOT a patch signature)", re.compile(
        rb"\xe8.{4}\x85\xc0\x0f\x84.{4}",
        re.DOTALL,
    )),
    ("CALL/TEST/JE-short (generic; NOT a patch signature)", re.compile(
        rb"\xe8.{4}\x85\xc0\x74.",
        re.DOTALL,
    )),
)


def diagnose_p4_patterns(original, *, max_examples=8):
    """Return bounded, read-only byte evidence; NEVER returns patch offsets.

    All offsets are raw Framework *file* offsets. The caller must establish
    Mach-O section mapping and disassemble before assigning a source function.
    """
    if not 1 <= max_examples <= 24:
        raise ValueError("max_examples must be between 1 and 24")
    report = ["P4 READ-ONLY INSTRUCTION PROBES (not verified patch sites):"]
    for label, pattern in P4_DIAGNOSTIC_PATTERNS:
        count, examples = 0, []
        for match in pattern.finditer(original):
            count += 1
            if len(examples) < max_examples:
                start = match.start()
                lo = max(0, start - 20)
                hi = min(len(original), match.end() + 24)
                examples.append(
                    f"  offset 0x{start:x}: {original[lo:hi].hex(' ')}"
                )
        report.append(f"{label}: {count} match(es)")
        report.extend(examples)
        if count > len(examples):
            report.append(f"  ... {count - len(examples)} additional match(es) omitted")
    report.append(
        "These candidates are NOT safe patch locations. A P4 modification "
        "requires proof of GpuMain/Seatbelt control flow using disassembly."
    )
    return "\n".join(report)


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

    # On the user's exact known M157 binary, match the ENTIRE observed
    # instruction context including call and jump displacements. Do not
    # widen this to any of the thousands of generic call/test/jump sites.
    occurrences = original.count(P4_M157_CONTEXT)
    context_at = original.find(P4_M157_CONTEXT)
    if occurrences != 1 or context_at != P4_M157_CONTEXT_OFFSET:
        raise GraphicsCompatError(
            "P4 GPU Seatbelt candidate: expected one exact Chrome 157 "
            "instruction context at "
            f"0x{P4_M157_CONTEXT_OFFSET:x}; found {occurrences}, "
            f"first at 0x{context_at:x}; refusing unverified bypass"
        )
    offset = P4_M157_GUARD_OFFSET
    end = offset + len(P4_M157_GUARD_ORIGINAL)
    if original[offset:end] != P4_M157_GUARD_ORIGINAL:
        raise GraphicsCompatError("P4 original conditional branch differs")
    if modified[offset:end] != P4_M157_GUARD_ORIGINAL:
        raise GraphicsCompatError("P4 branch already modified in patch plan")

    # P1-P7 offsets are starts of independently verified regions. P3, P5-P7
    # have more than one modified instruction; compare conservative windows.
    for name, start in positions.items():
        span = 2 if name == "allowed_gl_jump" else 6 if name == "display_init_jump" else 80
        if offset < start + span and start < end:
            raise GraphicsCompatError(f"P4 instruction overlaps existing {name} region")

    data = bytearray(modified)
    data[offset:end] = P4_M157_GUARD_PATCHED
    new_positions = dict(positions)
    new_positions[P4_NAME] = offset
    return bytes(data), new_positions
