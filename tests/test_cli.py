import contextlib
import io
import json
import unittest
from http.client import BadStatusLine
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

from vallum_http.cli import main

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def invoke(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(list(args))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_hardened_exit_zero(self):
        code, output, _ = self.invoke("--headers", str(ROOT / "examples/hardened.headers"), "--origin", "https://demo.invalid/")
        self.assertEqual(code, 0)
        self.assertIn("0 high, 0 warning, 0 info", output)

    def test_json_findings_and_exit_one(self):
        code, output, _ = self.invoke("--headers", str(ROOT / "examples/needs-review.headers"), "--origin", "https://demo.invalid/", "--format", "json")
        result = json.loads(output)
        self.assertEqual(code, 1)
        self.assertEqual(result["schema_version"], 1)
        self.assertGreater(result["summary"]["warning"], 0)

    def test_fail_on_none_keeps_findings(self):
        code, output, _ = self.invoke("--headers", str(ROOT / "examples/needs-review.headers"), "--origin", "https://demo.invalid/", "--fail-on", "none")
        self.assertEqual(code, 0)
        self.assertIn("csp.inline_scripts", output)

    def test_origin_required(self):
        code, output, _ = self.invoke("--headers", str(ROOT / "examples/hardened.headers"), "--format", "json")
        self.assertEqual(code, 2)
        self.assertIn("--origin", json.loads(output)["error"]["message"])

    def test_no_network_in_offline_mode(self):
        with patch("vallum_http.cli.fetch", side_effect=AssertionError("Offline mode must not request a URL")):
            code, _, _ = self.invoke("--headers", str(ROOT / "examples/hardened.headers"), "--origin", "https://demo.invalid/")
        self.assertEqual(code, 0)

    def test_error_json_is_machine_readable(self):
        code, output, _ = self.invoke("--headers", "missing-file.headers", "--origin", "https://demo.invalid/", "--format", "json")
        self.assertEqual(code, 2)
        self.assertIn("error", json.loads(output))

    def test_json_is_deterministic(self):
        args = ("--headers", str(ROOT / "examples/needs-review.headers"), "--origin", "https://demo.invalid/", "--format", "json")
        self.assertEqual(self.invoke(*args), self.invoke(*args))

    def test_runtime_errors_do_not_echo_secret_details(self):
        failures = (
            URLError("https://demo.invalid/?token=private-token"),
            BadStatusLine("Set-Cookie: session=private-token"),
            UnicodeEncodeError("ascii", "/private-token/ž", 15, 16, "unsupported"),
            OSError("private-token"),
        )
        for failure in failures:
            for output_format in ("text", "json"):
                with self.subTest(failure=type(failure).__name__, output_format=output_format):
                    with patch("vallum_http.cli.fetch", side_effect=failure):
                        code, output, error = self.invoke("--url", "https://demo.invalid/?token=private-token", "--format", output_format)
                    self.assertEqual(code, 2)
                    self.assertNotIn("private-token", output + error)
                    if output_format == "json":
                        self.assertIn("error", json.loads(output))

    def test_invalid_url_port_is_private(self):
        code, output, _ = self.invoke("--url", "https://demo.invalid:private-port/?token=private-token", "--format", "json")
        self.assertEqual(code, 2)
        self.assertNotIn("private-port", output)
        self.assertNotIn("private-token", output)


if __name__ == "__main__":
    unittest.main()
