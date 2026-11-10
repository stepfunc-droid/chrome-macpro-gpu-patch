#!/usr/bin/env python3
"""Experimental macOS Chrome signing for an isolated *test copy*.

Based on Chromium's unbranded entitlements and signing part roles:
https://chromium.googlesource.com/chromium/src/+/main/chrome/installer/mac/signing/parts.py

This does NOT bypass AMFI, disable SIP, or disable library validation.
No signature change can make a modified Google Chrome copy Google-signed.
"""
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile

MAIN_CAPABILITIES = (
    "com.apple.security.device.audio-input",
    "com.apple.security.device.bluetooth",
    "com.apple.security.device.camera",
    "com.apple.security.device.print",
    "com.apple.security.device.usb",
    "com.apple.security.personal-information.location",
    "com.apple.security.personal-information.photos-library",
)
JIT_ENTITLEMENT = "com.apple.security.cs.allow-jit"
BRANDED_KEYS = (
    "com.apple.application-identifier",
    "keychain-access-groups",
    "com.apple.developer.associated-domains.applinks.read-write",
    "com.apple.developer.web-browser.public-key-credential",
)
# Chromium's helpers require JIT only for Renderer and GPU process roles.
JIT_HELPERS = ("(Renderer)", "(GPU)", "(Aperitif Renderer)", "(Aperitif GPU)")


class SigningError(Exception):
    pass


def run(argv):
    result = subprocess.run([str(arg) for arg in argv], capture_output=True, text=True)
    if result.returncode != 0:
        raise SigningError(
            f"{argv[0]} failed (exit {result.returncode}) on {argv[-1]}:\n{result.stderr[-1200:]}"
        )
    return result


def helper_entitlements(name):
    return {JIT_ENTITLEMENT: True} if any(role in name for role in JIT_HELPERS) else {}


def write_plist(path, entries):
    path.write_bytes(plistlib.dumps(entries))


def sign(path, *, entitlements=None, runtime=False):
    argv = ["/usr/bin/codesign", "--force", "--sign", "-"]
    if runtime:
        argv.extend(["--options", "runtime"])
    if entitlements is not None:
        argv.extend(["--entitlements", str(entitlements)])
    argv.append(str(path))
    run(argv)


def sign_test_copy(app):
    """Sign known Chromium components inside-out with no Google Team entitlements.

    The caller MUST pass a freshly staged test copy, never an installed app.
    Any unknown app/XPC parts fail closed instead of relying on --deep signing.
    """
    app = Path(app).resolve(strict=False)
    if not app.is_dir():
        raise SigningError(f"Staged test app does not exist: {app}")
    if app.name != "Google Chrome.app" or ".chrome-gl-test-" not in str(app.parent.name):
        raise SigningError("Only a temporary staged Google Chrome.app is eligible for signing")
    fw = app / "Contents/Frameworks/Google Chrome Framework.framework"
    version = fw / "Versions/Current"
    if not version.is_dir():
        raise SigningError("Cannot locate Chrome framework version directory")
    helpers = version / "Helpers"
    libs = version / "Libraries"
    if not (helpers.is_dir() and libs.is_dir()):
        raise SigningError("Missing Chrome Libraries or Helpers directory")

    with tempfile.TemporaryDirectory(prefix=".chrome-entitlements-", dir=str(app.parent)) as ent_dir:
        ent_dir = Path(ent_dir)
        main_plist = ent_dir / "main.plist"
        jit_plist = ent_dir / "jit.plist"
        write_plist(main_plist, {key: True for key in MAIN_CAPABILITIES})
        write_plist(jit_plist, {JIT_ENTITLEMENT: True})
        if set(plistlib.loads(main_plist.read_bytes())) & set(BRANDED_KEYS):
            raise SigningError("Branded Google entitlement unexpectedly present")

        # 1. Only the two ANGLE dylibs intentionally replaced in the staged
        # copy require re-signing. Do NOT enumerate Libraries: the original
        # Google Chrome M157 bundle can deny directory enumeration on macOS.
        # Leave other original, unmodified Google-signed dylibs untouched.
        libraries = [libs / "libEGL.dylib", libs / "libGLESv2.dylib"]
        for library in libraries:
            if not library.is_file():
                raise SigningError(f"Expected staged ANGLE library missing: {library}")
            print(f"[*] Signing staged ANGLE library: {library.name}", flush=True)
            sign(library)

        # 2. Helper applications, signing JIT roles separately from generic roles.
        helper_apps = sorted(p for p in helpers.iterdir() if p.is_dir() and p.suffix == ".app")
        if not helper_apps:
            raise SigningError("No Chrome Helper apps found")
        for helper in helper_apps:
            ent = jit_plist if helper_entitlements(helper.name) else None
            sign(helper, entitlements=ent, runtime=True)

        # 3. Known standalone helper executables.
        for name in ("chrome_crashpad_handler", "app_mode_loader",
                     "web_app_shortcut_copier"):
            binary = helpers / name
            if binary.exists() and binary.is_file():
                sign(binary, runtime=True)

        # 4. Unknown additional nested app extensions would require their own
        # signing policy, so refuse to guess.
        for folder in (version / "XPCServices", app / "Contents/PlugIns",
                       app / "Contents/XPCServices"):
            if folder.is_dir() and list(folder.iterdir()):
                raise SigningError(f"Unreviewed nested extension directory: {folder}")

        # 5. Framework then outer app. Never use --deep when signing.
        sign(fw)
        sign(app, entitlements=main_plist, runtime=True)
        run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)])
        print("[+] Isolated test app signed with Chromium-style, unbranded entitlements.")
        print("[!] This verifies on-disk signatures, not AMFI launch approval.")
