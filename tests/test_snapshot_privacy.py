import json
import unittest

from vallum_http.core import audit, parse_headers
from vallum_http.reporting import compare, sarif, snapshot
from dataclasses import asdict


class SnapshotPrivacyTests(unittest.TestCase):
    def findings(self, headers):
        response = parse_headers(headers, "https://private-host.invalid/private-path?token=private-query")
        return [asdict(f) for f in audit(response)]

    def test_snapshot_and_sarif_omit_host_path_query_and_raw_headers(self):
        findings = self.findings("HTTP/1.1 200 OK\nContent-Type: text/html\nSet-Cookie: private-cookie=private-value\nServer: private-server\nContent-Security-Policy: script-src https://private-csp.invalid\n")
        for result in (snapshot(findings, "fixture"), sarif(findings)):
            text = json.dumps(result)
            for secret in ("private-host", "private-path", "private-query", "private-cookie", "private-value", "private-server", "private-csp"):
                self.assertNotIn(secret, text)

    def test_cookie_reorder_does_not_claim_identity_changes(self):
        first = self.findings("Content-Type: application/json\nSet-Cookie: first=x\nSet-Cookie: second=y; Secure; HttpOnly; SameSite=Lax\n")
        second = self.findings("Content-Type: application/json\nSet-Cookie: second=y; Secure; HttpOnly; SameSite=Lax\nSet-Cookie: first=x\n")
        comparison = compare(snapshot(second, "fixture"), snapshot(first, "fixture"))
        self.assertEqual(comparison["summary"]["added"], 0)
        self.assertEqual(comparison["summary"]["resolved"], 0)

    def test_policy_fix_resolves_warning_without_claiming_vulnerability(self):
        first = self.findings("Content-Type: application/json\n")
        second = self.findings("Content-Type: application/json\nX-Content-Type-Options: nosniff\n")
        comparison = compare(snapshot(second, "fixture"), snapshot(first, "fixture"))
        self.assertEqual(comparison["resolved"], [{"rule_id": "content_type.nosniff_missing", "scope": "response", "severity": "warning", "count": 1}])
        self.assertEqual(comparison["summary"]["added"], 0)

    def test_cookie_value_change_is_intentionally_outside_snapshot(self):
        first = self.findings("Content-Type: application/json\nSet-Cookie: first=old-secret\n")
        second = self.findings("Content-Type: application/json\nSet-Cookie: first=new-secret\n")
        self.assertEqual(snapshot(first, "fixture"), snapshot(second, "fixture"))


if __name__ == "__main__":
    unittest.main()
