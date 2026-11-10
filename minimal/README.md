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
- Only operates on a new test copy in `~/Downloads/` by default (or another new path under your home).
  It checks the clean inputs' signatures and Google's Team ID (EQHXZ8M8AV), refuses ambiguous byte patterns,
  and verifies that signing succeeds before publishing the new copy.

**Caveat:** It is not possible to modify Chrome's signed framework without
changing its code identity. The test copy is signed **ad-hoc**, not by Google;
this can affect Chrome Safe Storage, Keychain access, browser updates,
privacy permissions, and other signature-bound behavior. **Do not sign in
to banking, exchanges, or other sensitive sites with this test build.**
The first implementation mistakenly used `codesign --deep --preserve-metadata`,
which retained Google Team ID entitlements on ad-hoc-signed code. A real
M157 test copy failed with `CODESIGNING: Taskgated Invalid Signature`.
Now `minimal/signing.py` signs known nested components inside-out with
Chromium's unbranded main-app capabilities and the JIT entitlement only
for Renderer/GPU helpers. It does not preserve Google-specific app identifiers
or Keychain groups. **It does not disable library validation** and can still
fail to launch: Chromium documents that self-signed builds can be
incompatible with its library validation settings. See:
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
- `~/Downloads/Chrome GPU Test.app` = **new output**, must not exist.

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
  --output "$HOME/Downloads/Chrome GPU Test.app" \
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
  --output "$HOME/Downloads/Chrome GPU Test.app" \
  --experimental-version --apply
```

This copies the source to a temporary folder in Downloads using `ditto --norsrc`,
removes only disallowed Finder/resource-fork extended attributes from that
**temporary copy**, and verifies the copied app still has Google's original
valid signature and Team ID **before** patching. This works around errors like
`resource fork, Finder information, or similar detritus not allowed` without
modifying the source. If the original code signature is actually invalid, it
still refuses to proceed. It then modifies the copied framework, copies the
two ANGLE libraries, ad-hoc signs and verifies the test copy, and finally
moves it to the specified output path. On error it deletes the temporary copy,
**never** the original browser.

If you omit `--output`, the script defaults to
`~/Downloads/Chrome GPU Test.app`.

### 3. Test with a disposable profile

Run the exact command printed by the script. It will resemble:

```bash
"$HOME/Downloads/Chrome GPU Test.app/Contents/MacOS/Google Chrome" \
  --user-data-dir="$HOME/Downloads/Chrome-GPU-Test-Profile" \
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

### Diagnose immediate SIGKILL on launch (no writes)

If the copied Chrome binary exits immediately with SIGKILL (even with
`--version`), do **not** change sandbox settings, SIP, or GPU patch
patterns yet. First collect the actual termination reason from the
macOS `.ips` crash report:

```bash
git pull origin experiment/minimal-chrome-gl
python3 minimal/inspect_crash.py
```

The report prints process path, code-signing identity, exception, and
termination, but not stack traces or full private crash contents. Ensure
`procPath` points to **Chrome GPU Test.app**, not your regular Chrome.
This project's ad-hoc signature currently preserves original Google
Chrome entitlements including the proprietary
`EQHXZ8M8AV.com.google.Chrome` application identifier and Google-only
Keychain groups. Chromium's signing docs explain that re-signing a
Google-branded Chrome build with those entitlements can prevent launch.
Do not mistake successful `codesign --verify` for launch permission.
This issue must be diagnosed before any further GPU patch changes.

### Diagnosing a staged Libraries permission error

If the staged copy reports `Operation not permitted` for
`.../Versions/<version>/Libraries`, the old implementation may have
been unable to enumerate that directory during signing, or an error during
staging cleanup may have hidden the real signing failure. The current
version signs only the explicitly replaced ANGLE dylibs and labels each
operation (use `--debug` to print the traceback). Cleanup errors are
reported separately rather than replacing the original error.

A failed run may leave a hidden temporary directory in Downloads named
`.chrome-gl-test-*`. Inspect the **specific** staging path printed in the
error before deleting it; never invoke `sudo rm -rf` over a wildcard.
These temporary files are not your official Chrome installation.

#### Confirmed cause of `codesign libEGL.dylib: Operation not permitted`

On the first M157 staging attempt, `ls -ldeO@` on the actual failed
`libEGL.dylib` showed the **`uchg` (user immutable)** BSD file flag.
That flag makes `codesign --force` fail and prevents cleanup from
unlinking the library. The old `shutil.copy2` call copied the donor's
metadata, including BSD flags. **Fixed:** donor ANGLE libraries now
use `shutil.copyfile` plus explicitly restoring just Unix file mode,
never copying source BSD flags or xattrs. The script also refuses to
overwrite symlinked destination libraries.

Existing orphan staging copies from old runs are *not* repaired
automatically. Do not run a broad recursive `chflags` or `sudo`.
For the specific already-inspected `libEGL.dylib`, it is reasonable
to use `chflags nouchg` on **that staged file only**, then inspect
other remaining staged files before deleting the old temp directory.
Never change the installed Chrome 151 donor or official Chrome 157.

### Rebuilding after a signature-invalid SIGKILL

If you already have `~/Downloads/Chrome GPU Test.app` created with the
old signing logic, **do not overwrite it**. Pull the updated branch
and create a separate output:

```bash
git pull origin experiment/minimal-chrome-gl

python3 minimal/patch_chrome.py \
  --source "$HOME/Downloads/Google Chrome.app" \
  --angle-from "/Applications/Google Chrome.app" \
  --output "$HOME/Downloads/Chrome GPU Test v2.app" \
  --experimental-version --apply
```

Check the new copy with:

```bash
codesign -d --entitlements :- "$HOME/Downloads/Chrome GPU Test v2.app" 2>/dev/null | plutil -p -

"$HOME/Downloads/Chrome GPU Test v2.app/Contents/MacOS/Google Chrome" --version
```

The entitlements should **not** include `EQHXZ8M8AV`-prefixed
Google identity or Keychain group entries. If `--version` exits with
SIGKILL, use `python3 minimal/inspect_crash.py` and verify that
`procPath` is the **v2** app, rather than making additional GPU patches.

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
