#!/usr/bin/env python3
"""Synthetic tests for two-object and single-object .ips formats."""
import json
from pathlib import Path
import tempfile
import unittest
from inspect_crash import parse_ips


class IPSParserTests(unittest.TestCase):
    def test_header_plus_report(self):
        header = {"bug_type": "309", "timestamp": "2026-11-10"}
        body = {"procPath": "/Users/example/Downloads/Chrome GPU Test.app/Contents/MacOS/Google Chrome",
                "termination": {"namespace": "CODESIGNING", "code": 2}}
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Google Chrome-test.ips"
            p.write_text(json.dumps(header) + "\n" + json.dumps(body) + "\n")
            parsed_header, parsed_body = parse_ips(p)
        self.assertEqual(parsed_header, header)
        self.assertEqual(parsed_body, body)

    def test_single_json_object(self):
        body = {"exception": {"signal": "SIGKILL"}}
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "Google Chrome-test.ips"
            p.write_text(json.dumps(body))
            header, report = parse_ips(p)
        self.assertEqual(header, {})
        self.assertEqual(report, body)


if __name__ == "__main__":
    unittest.main()
