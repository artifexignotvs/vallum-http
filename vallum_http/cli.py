from __future__ import annotations

import argparse
import json
import math
import sys
from http.client import HTTPException
from pathlib import Path
from urllib.error import URLError

from . import __version__
from .core import MAX_HEADER_BYTES, SEVERITY, audit, parse_headers, report, validate_url
from .network import fetch


def timeout_value(value: str) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not math.isfinite(result) or not 0.1 <= result <= 60:
        raise argparse.ArgumentTypeError("timeout must be between 0.1 and 60 seconds")
    return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Audit one HTTP response's security headers, with no runtime dependencies.")
    result.add_argument("--version", action="version", version=f"vallum-http {__version__}")
    source = result.add_mutually_exclusive_group(required=True)
    source.add_argument("--headers", metavar="FILE", help="read saved response headers; use - for standard input")
    source.add_argument("--url", help="request this one explicit HTTP(S) URL")
    result.add_argument("--origin", help="required with --headers: the URL that delivered the final saved response")
    result.add_argument("--method", choices=("HEAD", "GET"), default="HEAD", help="online request method (default: HEAD); response bodies are not read")
    result.add_argument("--timeout", type=timeout_value, default=10.0, help="per-request socket timeout in seconds, 0.1 to 60 (default: 10)")
    result.add_argument("--max-redirects", type=int, choices=range(6), default=0, metavar="0..5", help="same-host redirects to follow (default: 0); HTTPS downgrades are blocked")
    result.add_argument("--document", action="store_true", help="run HTML document checks even without an HTML Content-Type")
    result.add_argument("--format", choices=("text", "json"), default="text")
    result.add_argument("--fail-on", choices=("info", "warning", "high", "none"), default="warning", help="minimum finding severity producing exit 1 (default: warning)")
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser()
    args = arguments.parse_args(argv)
    try:
        if args.headers:
            if not args.origin:
                raise ValueError("--origin is required with --headers; use the final response URL")
            if args.method != "HEAD" or args.max_redirects or args.timeout != 10.0:
                raise ValueError("--method, --max-redirects, and --timeout apply only to --url")
            if args.headers == "-":
                raw = sys.stdin.buffer.read(MAX_HEADER_BYTES + 1)
            else:
                with Path(args.headers).open("rb") as stream:
                    raw = stream.read(MAX_HEADER_BYTES + 1)
            if len(raw) > MAX_HEADER_BYTES:
                raise ValueError("Header file exceeds 1 MiB")
            response = parse_headers(raw.decode("utf-8-sig"), args.origin)
            findings, history, mode = [], [], "offline"
        else:
            if args.origin:
                raise ValueError("--origin applies only to --headers")
            url = validate_url(args.url)
            response, findings, history = fetch(url, args.method, args.timeout, args.max_redirects)
            mode = "online"
        findings.extend(audit(response, document=args.document))
        findings.sort(key=lambda f: (-SEVERITY[f.severity], f.id, f.message))
        result = report(response, findings, mode, history)
    except (ValueError, UnicodeError, OSError, URLError, HTTPException) as exc:
        # Exceptiones externae inscriptiones, capita vel secreta revelare possunt.
        if isinstance(exc, UnicodeError):
            message = "Input contains text that cannot be decoded or encoded for this operation"
        elif isinstance(exc, (URLError, HTTPException)):
            message = "HTTP request failed; check connectivity, TLS configuration, and response syntax"
        elif isinstance(exc, OSError):
            message = "Cannot read saved headers; check the file path and permissions" if args.headers else "Network operation failed; check connectivity and target availability"
        else:
            message = str(exc)
        if args.format == "json":
            print(json.dumps({"schema_version": 1, "error": {"message": message}}, sort_keys=True))
        else:
            print(f"vallum-http: {message}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"VALLUM HTTP  {result['target']}")
        print(f"HTTP {response.status} | {mode} | {result['summary']['high']} high, {result['summary']['warning']} warning, {result['summary']['info']} info")
        for finding in findings:
            print(f"\n[{finding.severity.upper()}] {finding.id}: {finding.message}")
            print(f"  Next: {finding.recommendation}")
        if not findings:
            print("No findings in the implemented checks. This is not a security certification.")
    if args.fail_on == "none":
        return 0
    return int(any(SEVERITY[f.severity] >= SEVERITY[args.fail_on] for f in findings))
