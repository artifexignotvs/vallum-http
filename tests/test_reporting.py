import copy
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vallum_http.reporting import BaselineError, MAX_BASELINE_BYTES, artifact_value, compare, fail_new, load_baseline, sarif, snapshot, read_baseline
from vallum_http.cli import main

ROOT = Path(__file__).resolve().parents[1]


class ReportingTests(unittest.TestCase):
    def finding(self, severity="warning", location="mcpServers.server[1].args[2]"):
        return {"id": "cookie.secure_missing", "severity": severity, "message": "Cookie #1 lacks Secure.", "recommendation": "Review the cookie policy."}

    def baseline(self):
        return snapshot([self.finding()], "fixture")

    def invoke(self, args):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            code = main(args)
        return code, output.getvalue(), error.getvalue()

    def command(self):
        return ["--headers", str(ROOT / "examples/needs-review.headers"), "--origin", "https://demo.invalid/private-secret?token=hostile-secret"]

    def test_shipped_baseline_fixture_is_accepted(self):
        value = load_baseline((ROOT / "examples/review.baseline.json").read_bytes(), "synthetic-example")
        self.assertGreater(len(value["findings"]), 0)

    def test_snapshot_rejects_counts_it_cannot_load(self):
        with self.assertRaises(BaselineError):
            snapshot([self.finding()] * 100001, "fixture")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO fixtures require POSIX")
    def test_reader_rejects_fifo_symlink_and_directory_without_opening(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "baseline.json"
            target.write_text(json.dumps(self.baseline()))
            link = root / "link"
            link.symlink_to(target)
            pipe = root / "pipe"
            os.mkfifo(pipe)
            for value in (pipe, link, root):
                with self.subTest(path=value), patch("vallum_http.reporting.os.open", side_effect=AssertionError("Special file opened")):
                    with self.assertRaises(BaselineError):
                        read_baseline(value, "fixture")
            self.assertEqual(read_baseline(target, "fixture"), self.baseline())

    def test_reader_detects_file_replacement_and_oversize_before_open(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, replacement = root / "first", root / "second"
            first.write_text(json.dumps(self.baseline()))
            replacement.write_text(json.dumps(self.baseline()))
            original, replaced = os.lstat(first), os.lstat(replacement)
            with patch("vallum_http.reporting.os.lstat", side_effect=[original, replaced]):
                with self.assertRaisesRegex(BaselineError, "changed"):
                    read_baseline(first, "fixture")
            with patch("vallum_http.reporting.MAX_BASELINE_BYTES", 8), patch("vallum_http.reporting.os.open", side_effect=AssertionError("Oversize file opened")):
                with self.assertRaises(BaselineError):
                    read_baseline(first, "fixture")

    def test_baseline_roundtrip(self):
        value = self.baseline()
        self.assertEqual(load_baseline(json.dumps(value).encode(), "fixture"), value)

    def test_untrusted_baseline_rejects_unknown_fields_and_incompatible_types(self):
        source = self.baseline()
        mutations = [lambda v: v.update(extra="hostile-secret"),
                     lambda v: v.update(schema_version=True),
                     lambda v: v.update(schema_version=2),
                     lambda v: v.update(tool="other"),
                     lambda v: v.update(tool_version="0.1.0"),
                     lambda v: v.update(tool_version=[]),
                     lambda v: v.update(label="different"),
                     lambda v: v.update(label="\x1b[31mhostile-secret"),
                     lambda v: v.update(comparison_scope="other"),
                     lambda v: v.update(findings={}),
                     lambda v: v["findings"][0].update(rule_id="hostile-secret"),
                     lambda v: v["findings"][0].update(scope="/private/hostile-secret"),
                     lambda v: v["findings"][0].update(severity="other"),
                     lambda v: v["findings"][0].update(count=0),
                     lambda v: v["findings"][0].update(count=True),
                     lambda v: v["findings"][0].update(count=1.2),
                     lambda v: v["findings"][0].update(count=100001),
                     lambda v: v["findings"][0].update(message="hostile-secret"),
                     lambda v: v["findings"].append(copy.deepcopy(v["findings"][0]))]
        for mutate in mutations:
            value = copy.deepcopy(source)
            mutate(value)
            with self.subTest(value=value):
                with self.assertRaises(BaselineError) as error:
                    load_baseline(json.dumps(value).encode(), "fixture")
                self.assertNotIn("hostile-secret", str(error.exception))

    def test_baseline_invalid_json_and_resource_bounds(self):
        for data in (b"[]", b"{", b"null", b'"string"', b"NaN", b'{"x":1,"x":2}', b"\xff", b"x" * (MAX_BASELINE_BYTES + 1), b"[" * 2000):
            with self.subTest(prefix=data[:20]):
                with self.assertRaises(BaselineError):
                    load_baseline(data, "fixture")

    def test_same_findings_are_unchanged(self):
        result = compare(self.baseline(), self.baseline())
        self.assertEqual(result["summary"], {"added": 0, "resolved": 0, "unchanged": 1, "severity_changed": 0})
        self.assertFalse(fail_new(result, "warning"))

    def test_add_and_resolve_counts(self):
        one = self.baseline()
        two = snapshot([self.finding(), self.finding()], "fixture")
        self.assertEqual(compare(two, one)["summary"]["added"], 1)
        self.assertEqual(compare(one, two)["summary"]["resolved"], 1)
        self.assertTrue(fail_new(compare(two, one), "warning"))
        self.assertFalse(fail_new(compare(one, two), "warning"))

    def test_severity_changes_are_distinct_from_new_and_resolved(self):
        old = snapshot([self.finding("info")], "fixture")
        new = snapshot([self.finding("high")], "fixture")
        change = compare(new, old)
        self.assertEqual(change["summary"], {"added": 0, "resolved": 0, "unchanged": 0, "severity_changed": 1})
        self.assertEqual(change["severity_changed"][0]["from"], "info")
        self.assertTrue(fail_new(change, "high"))
        self.assertFalse(fail_new(compare(old, new), "info"))
        self.assertFalse(fail_new(change, "none"))

    def test_aggregate_matching_never_uses_ordinal_or_message_identity(self):
        first = self.finding(location="mcpServers.server[1].args[2]")
        second = self.finding(location="mcpServers.server[8].args[9]")
        second["message"] = "Different explanatory wording"
        self.assertEqual(snapshot([first], "fixture"), snapshot([second], "fixture"))

    def test_sarif_structure_and_fingerprints_are_deterministic(self):
        result = sarif([self.finding(), self.finding()])
        self.assertEqual(result["version"], "2.1.0")
        run = result["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "vallum-http")
        self.assertEqual(len(run["results"]), 1)
        self.assertEqual(run["results"][0]["properties"]["count"], 2)
        self.assertEqual(len(run["results"][0]["partialFingerprints"]["ruleScope/v1"]), 64)
        self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"], 1)
        self.assertEqual(result, sarif([self.finding(), self.finding()]))

    def test_sarif_public_artifact_and_execution_errors(self):
        result = sarif([self.finding()], artifact="reports/public.json", errors=["hostile-secret"])
        run = result["runs"][0]
        self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "reports/public.json")
        self.assertFalse(run["invocations"][0]["executionSuccessful"])
        self.assertNotIn("hostile-secret", json.dumps(result))

    def test_sarif_rejects_private_or_hostile_artifact_paths(self):
        for path in ("/private/file", "../secret", "reports/../secret", "https://host/x", "a//b", "a/./b", "C:\\x", "secret?x=1", "\x1b[31m", "a b"):
            with self.subTest(path=path):
                with self.assertRaises(BaselineError):
                    artifact_value(path)

    def test_cli_baseline_new_gate_and_exclusive_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "baseline.json")
            args = self.command() + ["--format", "json", "--baseline-label", "fixture"]
            code, output, _ = self.invoke(args + ["--write-baseline", path])
            self.assertEqual(code, 1)
            original = Path(path).read_bytes()
            code, output, _ = self.invoke(args + ["--baseline", path, "--fail-on-new"])
            self.assertEqual(code, 0)
            self.assertGreater(json.loads(output)["comparison"]["summary"]["unchanged"], 0)
            code, output, _ = self.invoke(args + ["--baseline", path])
            self.assertEqual(code, 1)
            code, output, _ = self.invoke(args + ["--write-baseline", path])
            self.assertEqual(code, 2)
            self.assertEqual(Path(path).read_bytes(), original)

    def test_cli_added_findings_fail_new_and_disabled_threshold_succeeds(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.json"
            path.write_text(json.dumps(snapshot([], "fixture")))
            args = self.command() + ["--format", "json", "--baseline", str(path), "--baseline-label", "fixture", "--fail-on-new"]
            code, output, _ = self.invoke(args)
            self.assertEqual(code, 1)
            self.assertGreater(json.loads(output)["comparison"]["summary"]["added"], 0)
            code, _, _ = self.invoke(args + ["--fail-on", "none"])
            self.assertEqual(code, 0)

    def test_baseline_total_count_is_bounded(self):
        value = self.baseline()
        value["findings"][0]["count"] = 60000
        other = copy.deepcopy(value["findings"][0])
        other["severity"] = "high"
        value["findings"].append(other)
        with self.assertRaises(BaselineError):
            load_baseline(json.dumps(value).encode(), "fixture")

    def test_cli_malformed_baseline_prevents_completed_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-secret.json"
            path.write_text('{"hostile-secret": true}')
            for output_format in ("json", "sarif"):
                code, output, error = self.invoke(self.command() + ["--baseline", str(path), "--baseline-label", "fixture", "--format", output_format])
                self.assertEqual(code, 2)
                self.assertNotIn("hostile-secret", output + error)
                self.assertNotIn("private-secret", output + error)
                self.assertIsInstance(json.loads(output), dict)

    def test_cli_option_contract_errors(self):
        for flags in (["--fail-on-new"], ["--baseline", "missing"], ["--baseline-label", "fixture"], ["--sarif-artifact", "reports/output.json"]):
            code, _, _ = self.invoke(self.command() + list(flags))
            self.assertEqual(code, 2)

    def test_cli_sarif_is_parseable_without_automatic_input_path(self):
        code, output, error = self.invoke(self.command() + ["--format", "sarif"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output)["version"], "2.1.0")
        self.assertNotIn(str(ROOT), output + error)


if __name__ == "__main__":
    unittest.main()
