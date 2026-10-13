import json
import unittest
from pathlib import Path

from vallum_http.core import Response, audit, parse_headers, parse_policies, report, validate_url

ROOT = Path(__file__).resolve().parents[1]


def response(*headers, url="https://demo.invalid/", status=200):
    return Response(url, status, tuple(headers))


def identifiers(item, document=False):
    return {finding.id for finding in audit(item, document)}


class ParserTests(unittest.TestCase):
    def test_final_block_and_duplicate_cookies_are_preserved(self):
        raw = "HTTP/1.1 301 Moved\r\nLocation: /final\r\n\r\nHTTP/2 200\r\nSet-Cookie: a=x\r\nSet-Cookie: b=y\r\n\r\n"
        parsed = parse_headers(raw, "https://demo.invalid/final")
        self.assertEqual(parsed.status, 200)
        self.assertEqual(parsed.values("SET-cookie"), ["a=x", "b=y"])

    def test_header_only_input(self):
        self.assertEqual(parse_headers("Content-Type: text/plain\n", "https://demo.invalid/").status, 200)

    def test_invalid_input_is_rejected(self):
        for text in ("", "\n", "broken", "Bad Name: x", "X: a\x00b", "X: a\vOther: b", "X: a\rOther: b", "X: a\n continuation", "HTTP/2 200\nX: y\n\nbody", "HTTP/1.1 100 Continue\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_headers(text, "https://demo.invalid/")

    def test_invalid_urls_are_rejected(self):
        for url in ("file:///tmp/a", "https://user:secret@demo.invalid/", "https://demo.invalid:0/", "https://demo.invalid:99999/", "https://demo.invalid/\nX", "https://demo.invalid\\evil/"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_url(url)

    def test_url_normalization(self):
        self.assertEqual(validate_url("HTTPS://DEMO.INVALID#ignored"), "https://demo.invalid/")
        self.assertEqual(validate_url("http://[::1]:8080/test"), "http://[::1]:8080/test")

    def test_ambiguous_authorities_and_percent_escapes_are_rejected(self):
        for url in ("https://[::1]ignored/", "https://[v1.anything]/", "https://[fe80::1%25eth0]/", "https://demo.invalid:/", "https://bad..invalid/", "https://%64emo.invalid/", "https://demo.invalid/%zz", "https://demo.invalid/%?ab"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_url(url)

    def test_unicode_urls_are_encoded_without_changing_existing_escapes(self):
        self.assertEqual(validate_url("https://münich.invalid/café%20record?q=ž"), "https://xn--mnich-kva.invalid/caf%C3%A9%20record?q=%C5%BE")

    def test_url_errors_do_not_echo_sensitive_authority(self):
        with self.assertRaises(ValueError) as caught:
            validate_url("https://demo.invalid:private-port/?token=private-query")
        self.assertNotIn("private-port", str(caught.exception))
        self.assertNotIn("private-query", str(caught.exception))

    def test_first_duplicate_csp_directive_wins(self):
        policies, duplicate = parse_policies(["script-src 'none'; script-src *"])
        self.assertTrue(duplicate)
        self.assertEqual(policies[0]["script-src"], ["'none'"])


class PolicyTests(unittest.TestCase):
    def test_hardened_example_has_no_findings(self):
        parsed = parse_headers((ROOT / "examples/hardened.headers").read_text(), "https://demo.invalid/")
        self.assertEqual(audit(parsed), [])

    def test_hsts_on_http_does_not_count(self):
        found = identifiers(response(("Strict-Transport-Security", "max-age=31536000"), url="http://demo.invalid/"))
        self.assertIn("transport.http", found)
        self.assertIn("hsts.insecure", found)
        self.assertNotIn("hsts.missing", found)

    def test_hsts_duplicate_directive_invalid(self):
        found = identifiers(response(("Strict-Transport-Security", "max-age=5; MAX-AGE=10")))
        self.assertIn("hsts.invalid", found)

    def test_hsts_zero_and_quoted_zero(self):
        for value in ("max-age=0", 'max-age="000"'):
            self.assertIn("hsts.disabled", identifiers(response(("Strict-Transport-Security", value))))

    def test_hsts_first_header_controls(self):
        found = identifiers(response(("Strict-Transport-Security", "max-age=0"), ("Strict-Transport-Security", "max-age=31536000")))
        self.assertIn("hsts.disabled", found)
        self.assertIn("hsts.multiple", found)

    def test_hsts_ip_literal_is_not_a_domain_policy(self):
        found = identifiers(response(url="https://127.0.0.1/"))
        self.assertIn("hsts.ip_literal", found)
        self.assertNotIn("hsts.missing", found)

    def test_json_avoids_document_findings(self):
        found = identifiers(response(("Content-Type", "application/json")))
        self.assertNotIn("csp.missing", found)
        self.assertNotIn("framing.missing", found)
        self.assertIn("csp.missing", identifiers(response(("Content-Type", "application/json")), document=True))

    def test_multiple_csp_policies_intersect(self):
        found = identifiers(response(("Content-Security-Policy", "script-src * 'unsafe-inline' 'unsafe-eval'"),
                                     ("Content-Security-Policy", "script-src 'none'")), document=True)
        self.assertFalse({"csp.inline_scripts", "csp.eval", "csp.broad_scripts"} & found)

    def test_comma_separated_csp_policies_intersect(self):
        found = identifiers(response(("Content-Security-Policy", "script-src *, script-src 'none'")), document=True)
        self.assertNotIn("csp.broad_scripts", found)

    def test_nonce_disables_unsafe_inline_in_modern_csp(self):
        found = identifiers(response(("Content-Security-Policy", "script-src 'unsafe-inline' 'nonce-YWJjZA=='")), document=True)
        self.assertNotIn("csp.inline_scripts", found)

    def test_strict_dynamic_ignores_broad_sources(self):
        found = identifiers(response(("Content-Security-Policy", "script-src https: 'unsafe-inline' 'strict-dynamic' 'nonce-YWJjZA=='")), document=True)
        self.assertNotIn("csp.inline_scripts", found)
        self.assertNotIn("csp.broad_scripts", found)

    def test_script_element_directive_overrides_default(self):
        found = identifiers(response(("Content-Security-Policy", "default-src 'none'; script-src-elem * 'unsafe-inline'")), document=True)
        self.assertIn("csp.inline_scripts", found)
        self.assertIn("csp.broad_scripts", found)
        self.assertNotIn("csp.eval", found)

    def test_report_only_is_not_enforcement(self):
        found = identifiers(response(("Content-Security-Policy-Report-Only", "default-src 'none'; frame-ancestors 'none'")), document=True)
        self.assertIn("csp.missing", found)
        self.assertIn("csp.report_only", found)
        self.assertIn("framing.missing", found)

    def test_frame_ancestors_overrides_xfo(self):
        found = identifiers(response(("Content-Security-Policy", "frame-ancestors *"), ("X-Frame-Options", "DENY")), document=True)
        self.assertIn("framing.wildcard", found)

    def test_frame_ancestors_intersection_is_respected(self):
        found = identifiers(response(("Content-Security-Policy", "frame-ancestors *, frame-ancestors 'none'")), document=True)
        self.assertNotIn("framing.wildcard", found)

    def test_default_src_is_not_frame_ancestors_fallback(self):
        found = identifiers(response(("Content-Security-Policy", "default-src 'none'")), document=True)
        self.assertIn("framing.missing", found)

    def test_referrer_uses_last_recognized_value(self):
        item = response(("Referrer-Policy", "unsafe-url, no-referrer, future-policy"))
        self.assertNotIn("referrer.permissive", identifiers(item, document=True))
        self.assertIn("referrer.permissive", identifiers(response(("Referrer-Policy", "no-referrer, unsafe-url")), document=True))

    def test_nosniff_duplicate_is_ambiguous(self):
        self.assertIn("content_type.nosniff_invalid", identifiers(response(("X-Content-Type-Options", "nosniff"), ("X-Content-Type-Options", "none"))))


class CookieTests(unittest.TestCase):
    def test_cookie_values_and_names_are_omitted(self):
        item = response(("Set-Cookie", "private_name=secret-value; SameSite=None"), url="https://demo.invalid/?token=secret-query#fragment")
        payload = json.dumps(report(item, audit(item), "offline"))
        for sensitive in ("private_name", "secret-value", "secret-query", "fragment"):
            self.assertNotIn(sensitive, payload)

    def test_samesite_none_requires_secure(self):
        self.assertIn("cookie.samesite_none_insecure", identifiers(response(("Set-Cookie", "a=b; SameSite=None"))))

    def test_host_prefix_requirements(self):
        self.assertIn("cookie.host_prefix", identifiers(response(("Set-Cookie", "__Host-session=value; Secure; Path=/; Domain=demo.invalid"))))
        self.assertNotIn("cookie.host_prefix", identifiers(response(("Set-Cookie", "__Host-session=value; Secure; Path=/"))))

    def test_prefix_is_case_sensitive(self):
        self.assertNotIn("cookie.host_prefix", identifiers(response(("Set-Cookie", "__host-session=value"))))

    def test_secure_prefix_requires_secure_origin(self):
        item = response(("Set-Cookie", "__Secure-session=value; Secure"), url="http://demo.invalid/")
        self.assertIn("cookie.secure_prefix", identifiers(item))

    def test_httponly_omission_is_informational(self):
        found = next(f for f in audit(response(("Set-Cookie", "a=b"))) if f.id == "cookie.httponly_missing")
        self.assertEqual(found.severity, "info")


if __name__ == "__main__":
    unittest.main()
