# Minimal Chrome ANGLE/OpenGL experiment (Kepler/OCLP)

**Status: experimental, NOT a verified Chrome 157 fix.** This is an
independent alternative to the upstream multi-browser patcher, intended
for testing a *copy* of Google Chrome on an Intel Mac with legacy OCLP GPU
drivers. It does **not** patch your everyday Chrome installation.

## Scope / security choices

- Two framework edits only: Chromium's OpenGL allowlist check and ANGLE
  display-initialization jump (patterns derived from the upstream project).
- **No** `Seatbelt::IsSandboxed()` or GPU sandbox edits.
- **No** `ScopedEGLSurfaceIOSurface::ValidateTarget()` bypass.
- **No** GPU mode fallback override and no IOSurface texture-target edits.
- **No** launcher replacement, background agents, cron, software downloads,
  automatic browser updates, repository self-updates, root privileges, or
  `--no-sandbox` flags.
- **No** use of the upstream repository's opaque `angle_dylibs/` binaries:
  the ANGLE libraries must be supplied from your *own genuine Chrome 151*
  app bundle. They may still be ABI-incompatible with newer Chrome versions.
- Only operates on a new, explicitly named output app **under your home**.
  It checks the clean inputs' signatures and Google's Team ID (EQHXZ8M8AV), refuses ambiguous byte patterns,
  and verifies that signing succeeds before publishing the new copy.

**Caveat:** It is not possible to modify Chrome's signed framework without
changing its code identity. The test copy is signed **ad-hoc**, not by Google;
this can affect Chrome Safe Storage, Keychain access, browser updates,
privacy permissions, and other signature-bound behavior. **Do not sign in
to banking, exchanges, or other sensitive sites with this test build.**
Google's Chromium signing documentation warns that locally signed Chrome-branded
builds can fail because official Chrome entitlements are identity-bound and
self-signed identities conflict with library validation. This experiment
**does not bypass library validation**; it may fail to launch even after
code-signature verification succeeds. See:
https://chromium.googlesource.com/chromium/src/+/main/chrome/installer/mac/signing/README.md

Do not copy your real Chrome profile into the test build. The main goal
of this first version is to see whether a GPU process can start without
removing a sandbox assertion.

## Requirements

- Intel/x86_64 Mac running macOS with OCLP legacy GPU support.
- A *clean* official latest Google Chrome app bundle to test, **separate**
  from your current Chrome 151.
- A *clean* official Chrome 151 app bundle to donate `libEGL.dylib` and
  `libGLESv2.dylib`. If those files do not exist, stop; the script
  deliberately does not fall back to the project-bundled binaries.
- Python 3.9+ and the built-in `ditto` and `codesign` programs.
- Adequate free disk space for a full additional Chrome bundle.

Example layout (adjust paths to your actual copies):

- `/Applications/Google Chrome.app` = your **current Chrome 151** (donor).
- `~/Downloads/Google Chrome.app` = a **newer clean official Chrome** (input).
- `~/Applications/Chrome GPU Test.app` = **new output**, must not exist.

### Read-only diagnostics for a new Chromium milestone

If a newer version says "Display initialization check not unique or absent",
the patcher **has not modified anything**. Get a bounded byte-pattern report:

```bash
python3 minimal/patch_chrome.py --diagnose   --source "$HOME/Downloads/Google Chrome.app"
```

Paste the terminal report into the discussion/PR so we can identify how
that particular Chromium build changed. **Do not force a pattern match.**
The reported offsets are only diagnostics, never automatically patched.

### 1. Dry run (default: no writes)

```bash
python3 minimal/patch_chrome.py \
  --source "$HOME/Downloads/Google Chrome.app" \
  --angle-from "/Applications/Google Chrome.app" \
  --output "$HOME/Applications/Chrome GPU Test.app" \
  --experimental-version
```

The optional `--experimental-version` flag is **required** outside the
older M152/M153 milestone range. It only allows the scanner to try exact
signatures; it does **not** establish compatibility with M157.

If either expected byte pattern is missing or ambiguous, the tool refuses
to patch. It does not attempt heuristic patching of arbitrary bytes.

### 2. Create the test copy (only after reviewing dry-run output)

```bash
python3 minimal/patch_chrome.py \
  --source "$HOME/Downloads/Google Chrome.app" \
  --angle-from "/Applications/Google Chrome.app" \
  --output "$HOME/Applications/Chrome GPU Test.app" \
  --experimental-version --apply
```

This copies the source to a temporary folder, modifies the copied framework,
copies the two ANGLE libraries, re-signs and verifies the copy, and only
then moves it to the output path. On error it deletes the temporary copy,
**never** the original browser.

### 3. Test with a disposable profile

Run the exact command printed by the script. It will resemble:

```bash
"$HOME/Applications/Chrome GPU Test.app/Contents/MacOS/Google Chrome" \
  --user-data-dir="$HOME/Applications/Chrome-GPU-Test-Profile" \
  --use-angle=gl --ignore-gpu-blocklist --no-first-run
```

The `--ignore-gpu-blocklist` switch overrides Chrome's GPU exclusions;
it is **only** intended for this experimental test session. If possible,
test first **without** it as well.

Visit `chrome://gpu`, and check:
- `Graphics Feature Status` (especially Compositing and WebGL).
- `GL_RENDERER` / ANGLE renderer, to rule out SwiftShader/software.
- `Log Messages` / GPU process crashes, plus `chrome://version`.

An ad-hoc signature verification passing is **not** proof of rendering
success. Missing shaders, ABI drift, IOSurface incompatibilities, or
GPU sandbox errors may still cause software fallback or crashes.
If the safe two-patch approach fails, collect the GPU logs before deciding
whether any additional change is justified. **Never** turn off the full
browser sandbox merely to make the probe pass.

### Restore / clean up

Close the test browser, then remove only the `Chrome GPU Test.app` and
`Chrome-GPU-Test-Profile` folders you created. Your existing signed Chrome
and Google profile have not been modified. Do not use the upstream
`--restore` flow on your original Chrome for this experiment.

### Local tests (pattern logic only)

```bash
python3 -m unittest discover -s minimal -p 'test_*.py'
```

These synthetic tests check binary offsets and rejection cases; they cannot
simulate a real Chrome GPU process. No Kepler/M157 runtime validation has
been performed by this project.
