"""Standalone negative and boundary tests for the auxiliary C++ parser."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


class ParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.temp.name) / "mcp-inspect"
        root = Path(__file__).resolve().parents[1]
        subprocess.run(["g++", "-std=c++17", "-Wall", "-Wextra", "-Wpedantic",
                        "-Werror", "-I" + str(root / "include"),
                        str(root / "src/main.cpp"), "-o", str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def response(self, raw):
        result = subprocess.run([str(self.binary)], input=raw + b"\n",
                                capture_output=True, check=True, timeout=5)
        return json.loads(result.stdout)

    def test_escaped_method_and_injection_are_inspected(self):
        for raw in [br'{"method":"tools\u002fcall","params":{"q":"ignore previous"}}',
                    br'{"method":"tools/call","params":{"q":"\u0069gnore previous"}}']:
            with self.subTest(raw=raw):
                self.assertEqual(self.response(raw)["decision"], "block")

    def test_decoded_duplicate_keys_are_rejected(self):
        for raw in [br'{"method":"initialize","\u006dethod":"tools/call"}',
                    br'{"method":"tools/call","params":{"a":1,"\u0061":2}}']:
            self.assertEqual(self.response(raw)["decision"], "block")

    def test_valid_unicode_round_trip(self):
        for method in ["caf\u00e9", "\U0001f600", "a\u0000b"]:
            raw = json.dumps({"method": method}, ensure_ascii=True).encode()
            self.assertEqual(self.response(raw)["reason"], "Non-tool-call method: " + method)

    def test_malformed_unicode_and_controls_are_rejected(self):
        for value in [br'"\uZZZZ"', br'"\uD800"', br'"\uDC00"',
                      br'"\uD800\u0041"', b'"a\x01b"', b'"\xc0\xaf"',
                      b'"\xed\xa0\x80"', b'"\xf4\x90\x80\x80"', b'"\x80"']:
            with self.subTest(value=value):
                self.assertEqual(self.response(b'{"method":' + value + b'}')["decision"], "block")

    def test_invalid_number_grammar_is_rejected(self):
        for value in [b"01", b"1+2", b"1-2", b"1.2.3", b"1e", b"1e+", b"1.", b".1", b"+1", b"--1"]:
            with self.subTest(value=value):
                self.assertEqual(self.response(b'{"method":"initialize","id":' + value + b'}')["decision"], "block")

    def test_valid_number_grammar_stays_allowed(self):
        for value in [b"0", b"-0", b"123", b"-1.25", b"1e+2", b"1E-2"]:
            self.assertEqual(self.response(b'{"method":"initialize","id":' + value + b'}')["decision"], "allow")

    def test_depth_boundary_fails_closed_and_process_survives(self):
        for depth, expected in [(64, "allow"), (65, "block"), (2000, "block")]:
            raw = b'[' * (depth - 1) + b'{"method":"initialize"}' + b']' * (depth - 1)
            with self.subTest(depth=depth):
                result = subprocess.run([str(self.binary)], input=raw + b'\n{"method":"initialize"}\n',
                                        capture_output=True, check=True, timeout=5)
                lines = result.stdout.splitlines()
                self.assertEqual(len(lines), 2)
                self.assertEqual(json.loads(lines[0])["decision"], expected)
                self.assertEqual(json.loads(lines[1])["decision"], "allow")


if __name__ == "__main__":
    unittest.main()
