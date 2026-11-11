#!/usr/bin/env python3
"""Read-only summary of recent Google Chrome macOS .ips crash reports.

Prints only high-level termination/signature fields, not full crash contents.
Does not require sudo or alter anything.
"""
import argparse
import json
from pathlib import Path
import sys


def parse_ips(path):
    raw = path.read_text(encoding="utf-8", errors="replace").lstrip()
    decoder = json.JSONDecoder()
    first, index = decoder.raw_decode(raw)
    rest = raw[index:].lstrip()
    # On recent macOS, .ips contains a JSON header object followed by
    # the separate detailed JSON report object.
    if rest:
        second, _ = decoder.raw_decode(rest)
        return first, second
    return {}, first


def compact(value):
    if value is None:
        return "(not present)"
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--folder", default="~/Library/Logs/DiagnosticReports")
    parser.add_argument("--count", type=int, default=3)
    args = parser.parse_args(argv)
    if not 1 <= args.count <= 20:
        parser.error("--count must be between 1 and 20")
    folder = Path(args.folder).expanduser()
    if not folder.is_dir():
        parser.error(f"Crash report folder does not exist: {folder}")
    reports = sorted(folder.glob("Google Chrome-*.ips"),
                     key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        print("No matching Google Chrome .ips reports found")
        return 1
    for f in reports[:args.count]:
        print(f"\n=== {f.name} ===")
        try:
            header, body = parse_ips(f)
        except (OSError, json.JSONDecodeError, ValueError) as e:
            print(f"Unable to parse: {e}")
            continue
        for field in ("timestamp", "procName", "procPath", "pid", "parentProc",
                      "parentPid", "codeSigningID", "codeSigningTeamID",
                      "codeSigningFlags", "codeSigningValidationCategory",
                      "exception", "termination", "terminationDescription"):
            val = body.get(field, header.get(field))
            if val is not None:
                print(f"{field}: {compact(val)}")
        if "procPath" not in body:
            print("Note: missing procPath, check if this report is for the test copy")
    print("\nThe report may not identify the root cause; do not infer GPU failure from SIGKILL alone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
