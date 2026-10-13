import ssl
import threading
import unittest
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from vallum_http.network import fetch


class FakeResponse:
    def __init__(self, code=200, **headers):
        self.code = code
        self.headers = Message()
        for key, value in headers.items():
            self.headers[key] = value
        self.closed = False

    def close(self):
        self.closed = True

    def read(self, *args):
        raise AssertionError("Response body must not be read")


class NetworkTests(unittest.TestCase):
    def run_responses(self, url, responses, **kwargs):
        with patch("vallum_http.network.build_opener") as builder:
            builder.return_value.open.side_effect = responses
            result = fetch(url, **kwargs)
            return result, builder

    def test_one_request_no_body_and_tls_verification(self):
        incoming = FakeResponse()
        (outgoing, _, _), builder = self.run_responses("https://demo.invalid/", [incoming])
        self.assertTrue(incoming.closed)
        self.assertEqual(outgoing.status, 200)
        self.assertEqual(builder.return_value.open.call_count, 1)
        request = builder.return_value.open.call_args.args[0]
        self.assertEqual(request.get_method(), "HEAD")
        context = builder.call_args.args[1]._context
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertEqual(builder.call_args.args[0].proxies, {})

    def test_redirect_default_is_zero(self):
        (outgoing, _, _), builder = self.run_responses("https://demo.invalid/", [FakeResponse(302, Location="/other")])
        self.assertEqual(outgoing.status, 302)
        self.assertEqual(builder.return_value.open.call_count, 1)

    def test_https_downgrade_never_followed(self):
        (_, findings, _), builder = self.run_responses("https://demo.invalid/", [FakeResponse(302, Location="http://demo.invalid/")], max_redirects=3)
        self.assertIn("redirect.downgrade", {f.id for f in findings})
        self.assertEqual(builder.return_value.open.call_count, 1)

    def test_cross_host_never_followed(self):
        (_, findings, _), builder = self.run_responses("https://demo.invalid/", [FakeResponse(302, Location="https://other.invalid/")], max_redirects=3)
        self.assertIn("redirect.cross_host", {f.id for f in findings})
        self.assertEqual(builder.return_value.open.call_count, 1)

    def test_cookie_jar_is_not_carried(self):
        first = FakeResponse(302, Location="/final?secret=yes")
        first.headers["Set-Cookie"] = "session=secret"
        (result, _, history), builder = self.run_responses("https://demo.invalid/?token=secret", [first, FakeResponse()], max_redirects=1)
        self.assertEqual(result.status, 200)
        self.assertEqual(builder.return_value.open.call_count, 2)
        second_request = builder.return_value.open.call_args.args[0]
        self.assertIsNone(second_request.get_header("Cookie"))
        self.assertNotIn("?", history[0]["from"])
        self.assertNotIn("?", history[0]["to"])

    def test_redirect_limit_is_exact(self):
        (_, findings, history), builder = self.run_responses("https://demo.invalid/", [FakeResponse(302, Location="/a"), FakeResponse(302, Location="/b")], max_redirects=1)
        self.assertEqual(builder.return_value.open.call_count, 2)
        self.assertEqual(len(history), 1)
        self.assertIn("redirect.limit", {f.id for f in findings})

    def test_redirect_loop_is_not_requested_again(self):
        (_, findings, _), builder = self.run_responses("https://demo.invalid/", [FakeResponse(302, Location="/")], max_redirects=2)
        self.assertIn("redirect.loop", {f.id for f in findings})
        self.assertEqual(builder.return_value.open.call_count, 1)

    def test_http_hop_is_preserved(self):
        (_, findings, _), _ = self.run_responses("http://demo.invalid/", [FakeResponse(301, Location="https://demo.invalid/"), FakeResponse()], max_redirects=2)
        self.assertIn("transport.http_hop", {f.id for f in findings})

    def test_redirect_credentials_rejected_before_second_request(self):
        with patch("vallum_http.network.build_opener") as builder:
            builder.return_value.open.return_value = FakeResponse(302, Location="https://user:secret@demo.invalid/")
            with self.assertRaises(ValueError):
                fetch("https://demo.invalid/", max_redirects=2)
            self.assertEqual(builder.return_value.open.call_count, 1)

    def test_malformed_redirect_errors_do_not_reveal_location(self):
        with patch("vallum_http.network.build_opener") as builder:
            builder.return_value.open.return_value = FakeResponse(302, Location="https://private-token＠demo.invalid/")
            with self.assertRaises(ValueError) as caught:
                fetch("https://demo.invalid/", max_redirects=2)
            self.assertNotIn("private-token", str(caught.exception))
            self.assertEqual(builder.return_value.open.call_count, 1)

    def test_library_method_restricted(self):
        with self.assertRaises(ValueError):
            fetch("https://demo.invalid/", method="DELETE")


class LocalTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requests = []
        requests = cls.requests

        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                requests.append((self.command, self.path))
                self.send_response(302 if self.path == "/start" else 200)
                if self.path == "/start":
                    self.send_header("Location", "/final")
                self.send_header("Content-Type", "text/plain")
                self.send_header("Set-Cookie", "first=one; Secure")
                self.send_header("Set-Cookie", "second=two; Secure")
                self.end_headers()

            def do_GET(self):
                self.do_HEAD()

            def log_message(self, *args):
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=5)

    def setUp(self):
        self.requests.clear()

    def test_real_head_preserves_repeated_headers(self):
        item, _, _ = fetch(self.url + "/final")
        self.assertEqual(len(item.values("set-cookie")), 2)
        self.assertEqual(self.requests, [("HEAD", "/final")])

    def test_real_redirect_is_bounded(self):
        item, _, history = fetch(self.url + "/start", max_redirects=1)
        self.assertEqual(item.status, 200)
        self.assertEqual(self.requests, [("HEAD", "/start"), ("HEAD", "/final")])
        self.assertEqual(len(history), 1)

    def test_explicit_get(self):
        fetch(self.url + "/final", method="GET")
        self.assertEqual(self.requests, [("GET", "/final")])


if __name__ == "__main__":
    unittest.main()
