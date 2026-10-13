from __future__ import annotations

import ssl
import math
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from . import __version__
from .core import MAX_HEADER_BYTES, Finding, Response, display_url, validate_url


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url: str, method: str = "HEAD", timeout: float = 10.0, max_redirects: int = 0) -> tuple[Response, list[Finding], list[dict]]:
    """Solum capita legit; transitus ad alium hospitem non sequitur."""
    if method not in {"HEAD", "GET"}:
        raise ValueError("Only HEAD and GET requests are supported")
    if not 0 <= max_redirects <= 5 or not math.isfinite(timeout) or not 0.1 <= timeout <= 60:
        raise ValueError("Redirect limit or timeout is outside supported bounds")
    url = validate_url(url)
    initial_host = urlsplit(url).hostname
    # Mandata interposita ex ambitu accepta iter occultum creare non debent.
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    findings: list[Finding] = []
    history: list[dict] = []
    visited = set()
    for hop in range(max_redirects + 1):
        visited.add(url)
        request = Request(url, method=method, headers={"User-Agent": f"vallum-http/{__version__}", "Accept": "*/*"})
        try:
            result = opener.open(request, timeout=timeout)
        except HTTPError as exc:
            result = exc
        try:
            headers = tuple(result.headers.raw_items())
            if sum(len(k.encode("utf-8")) + len(v.encode("utf-8")) for k, v in headers) > MAX_HEADER_BYTES:
                raise ValueError("Response headers exceed 1 MiB")
            response = Response(url, result.code, headers)
        finally:
            # Corpus responsi, etiam post GET, consulto non legitur.
            result.close()
        if response.status not in {301, 302, 303, 307, 308}:
            return response, findings, history
        locations = response.values("location")
        if len(locations) != 1:
            findings.append(Finding("redirect.invalid_location", "warning", "Redirect has no unique Location header.",
                                    "Return a single valid Location header."))
            return response, findings, history
        try:
            destination = validate_url(urljoin(url, locations[0]))
        except (UnicodeError, ValueError) as exc:
            raise ValueError("Redirect Location is not a valid HTTP(S) URL") from exc
        if urlsplit(url).scheme == "https" and urlsplit(destination).scheme == "http":
            findings.append(Finding("redirect.downgrade", "high", "HTTPS response redirects to unencrypted HTTP; it was not followed.",
                                    "Keep redirects on HTTPS."))
            return response, findings, history
        if hop >= max_redirects:
            if max_redirects:
                findings.append(Finding("redirect.limit", "info", "The configured redirect limit was reached.",
                                        "Inspect the redirect chain and select the final URL explicitly if appropriate."))
            return response, findings, history
        if urlsplit(destination).hostname != initial_host:
            findings.append(Finding("redirect.cross_host", "info", "A redirect to a different hostname was not followed.",
                                    "Audit the destination explicitly if it is in scope."))
            return response, findings, history
        if destination in visited:
            findings.append(Finding("redirect.loop", "warning", "A redirect loop was detected; the repeated URL was not requested again.",
                                    "Correct the redirect chain."))
            return response, findings, history
        history.append({"from": display_url(url), "to": display_url(destination), "status": response.status})
        if urlsplit(url).scheme == "http":
            if not any(f.id == "transport.http_hop" for f in findings):
                findings.append(Finding("transport.http_hop", "high", "The redirect chain included an unencrypted HTTP request.",
                                        "Start the audit and application navigation on HTTPS; initial HTTP traffic is not protected."))
        url = destination
    raise RuntimeError("Unreachable redirect state")
