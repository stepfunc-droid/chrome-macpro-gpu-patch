#!/usr/bin/env python3
"""Deprecated installer entrypoint: never modifies /Applications.

Use prepare_chrome.py to build a test app and launch script in ~/Downloads.
The user's decision to install is manual; --install is intentionally refused.
"""
import sys
from prepare_chrome import main as prepare_main

if __name__ == "__main__":
    args = sys.argv[1:]
    if "--install" in args:
        print("Automatic installation has been retired. "
              "Run python3 minimal/prepare_chrome.py; "
              "test the resulting App and move it manually.", file=sys.stderr)
        raise SystemExit(2)
    args = [arg for arg in args if arg != "--prepare-only"]
    raise SystemExit(prepare_main(args))
