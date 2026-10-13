from __future__ import annotations

import re
import ipaddress
from dataclasses import asdict, dataclass
from urllib.parse import quote, urlsplit, urlunsplit

MAX_HEADER_BYTES = 1024 * 1024
SEVERITY = {"info": 1, "warning": 2, "high": 3}
TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
STATUS = re.compile(r"^HTTP/\S+\s+([1-5][0-9]{2})(?:\s|$)")
NONCE_HASH = re.compile(r"^'(?:nonce-|sha(?:256|384|512)-)[A-Za-z0-9+/_-]+=*'$", re.I)


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    message: str
    recommendation: str


@dataclass(frozen=True)
class Response:
    url: str
    status: int
    headers: tuple[tuple[str, str], ...]

    def values(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k.lower() == name.lower()]


def validate_url(value: str) -> str:
    """Inscriptionem ante usum examinat et fragmentum removet."""
    if len(value) > 8192 or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ValueError("URL contains whitespace, control characters, or exceeds 8192 characters")
    if "\\" in value:
        raise ValueError("URL contains an unsupported backslash")
    try:
        parts = urlsplit(value)
        port = parts.port
        hostname = parts.hostname
        if parts.scheme not in {"http", "https"} or not hostname:
            raise ValueError("URL must use http or https and include a hostname")
        if parts.username is not None or parts.password is not None:
            raise ValueError("Credentials in URLs are not accepted")
        if not (port is None or 1 <= port <= 65535):
            raise ValueError("URL has an invalid authority or port")
        if parts.netloc.startswith("["):
            closing = parts.netloc.index("]")
            suffix = parts.netloc[closing + 1:]
            if (suffix and not re.fullmatch(r":[0-9]+", suffix)) or "%" in hostname:
                raise ValueError("URL has an invalid IPv6 authority")
            hostname = str(ipaddress.IPv6Address(hostname))
            authority = f"[{hostname}]"
        else:
            if parts.netloc.endswith(":"):
                raise ValueError("URL port is empty")
            hostname = hostname.encode("idna").decode("ascii").lower()
            labels = hostname.removesuffix(".").split(".")
            if len(hostname.removesuffix(".")) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in labels
            ):
                raise ValueError("URL hostname is invalid")
            authority = hostname
        if port is not None:
            authority += f":{port}"
        if any(re.search(r"%(?![0-9a-fA-F]{2})", component) for component in (parts.path, parts.query)):
            raise ValueError("URL has an invalid percent escape")
        path = quote(parts.path or "/", safe="/:@!$&'()*+,;=-._~%")
        query = quote(parts.query, safe="/?:@!$&'()*+,;=-._~%")
        return urlunsplit((parts.scheme, authority, path, query, ""))
    except (UnicodeError, ValueError) as exc:
        # Causa externa secreta continere potest; verba eius non referuntur.
        raise ValueError("Invalid HTTP(S) URL; check the hostname, port, credentials, and character encoding") from exc


def display_url(value: str) -> str:
    parts = urlsplit(value)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def parse_headers(text: str, origin: str) -> Response:
    """Ultimum capitum fasciculum legit; corpus responsi recusat."""
    if len(text.encode("utf-8")) > MAX_HEADER_BYTES:
        raise ValueError("Header file exceeds 1 MiB")
    origin = validate_url(origin)
    if any(ord(c) < 32 and c not in "\r\n\t" or ord(c) == 127 for c in text):
        raise ValueError("Header file contains a forbidden control character")
    if "\r" in text.replace("\r\n", ""):
        raise ValueError("Header file contains a bare carriage return")
    blocks: list[tuple[int, list[tuple[str, str]]]] = []
    headers: list[tuple[str, str]] = []
    status = 200
    closed = False
    started = False
    for number, line in enumerate(text.replace("\r\n", "\n").split("\n"), 1):
        match = STATUS.match(line)
        if match:
            if started:
                blocks.append((status, headers))
            status, headers, closed, started = int(match[1]), [], False, True
            continue
        if not line:
            if started:
                closed = True
            continue
        if closed:
            raise ValueError(f"Unexpected content after header block on line {number}; provide headers only")
        if line[0].isspace():
            raise ValueError(f"Obsolete folded header on line {number} is not supported")
        if ":" not in line:
            raise ValueError(f"Malformed header on line {number}")
        name, value = line.split(":", 1)
        if not TOKEN.fullmatch(name):
            raise ValueError(f"Invalid header name on line {number}")
        if any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in value):
            raise ValueError(f"Control character in header on line {number}")
        headers.append((name, value.strip()))
        started = True
    if started:
        blocks.append((status, headers))
    if not blocks:
        raise ValueError("Header file is empty")
    status, headers = blocks[-1]
    if status < 200:
        raise ValueError("Header file ends with an informational response")
    return Response(origin, status, tuple(headers))


def parse_policies(values: list[str]) -> tuple[list[dict[str, list[str]]], bool]:
    """Praeceptum primum servat, sicut norma iubet."""
    policies = []
    duplicate = False
    for value in values:
        for serialized in value.split(","):
            policy: dict[str, list[str]] = {}
            for directive in serialized.split(";"):
                words = directive.split()
                if not words:
                    continue
                name = words[0].lower()
                if name in policy:
                    duplicate = True
                    continue
                policy[name] = words[1:]
            policies.append(policy)
    return policies, duplicate


def script_sources(policy: dict[str, list[str]], element: bool = False) -> list[str] | None:
    names = ["script-src-elem", "script-src", "default-src"] if element else ["script-src", "default-src"]
    return next((policy[name] for name in names if name in policy), None)


def audit(response: Response, document: bool = False) -> list[Finding]:
    findings: list[Finding] = []

    def add(identifier: str, severity: str, message: str, recommendation: str) -> None:
        findings.append(Finding(identifier, severity, message, recommendation))

    secure = urlsplit(response.url).scheme == "https"
    try:
        ipaddress.ip_address(urlsplit(response.url).hostname or "")
        ip_literal = True
    except ValueError:
        ip_literal = False
    if not secure:
        add("transport.http", "high", "This response was delivered over unencrypted HTTP.",
            "Serve the endpoint over HTTPS; a redirect does not protect the initial HTTP request.")
    if response.status >= 400:
        add("response.error", "info", f"The endpoint returned HTTP {response.status}.",
            "Check the intended success response too; error responses may use different headers.")
    elif 300 <= response.status < 400:
        add("response.redirect", "info", "The inspected response is a redirect or cache-related response.",
            "Inspect the final document separately before drawing conclusions about its policy.")

    hsts = response.values("strict-transport-security")
    if not secure:
        if hsts:
            add("hsts.insecure", "info", "HSTS sent over HTTP is ignored by browsers.",
                "Send HSTS on HTTPS responses after checking HTTPS availability.")
    elif ip_literal:
        add("hsts.ip_literal", "info", "Browsers do not store HSTS policies for IP literals.",
            "Audit the hostname used by real visitors to assess HSTS coverage.")
    elif not hsts:
        add("hsts.missing", "warning", "No Strict-Transport-Security header was observed.",
            "Evaluate HSTS deployment after ensuring this host supports HTTPS consistently.")
    else:
        if len(hsts) > 1:
            add("hsts.multiple", "info", "Multiple HSTS headers were observed; the first is evaluated.",
                "Send one unambiguous HSTS header.")
        directives: dict[str, str | None] = {}
        malformed = False
        for piece in hsts[0].split(";"):
            if not piece.strip():
                continue
            name, separator, value = piece.strip().partition("=")
            name = name.strip().lower()
            if not TOKEN.fullmatch(name) or name in directives:
                malformed = True
            directives[name] = value.strip() if separator else None
        max_age = directives.get("max-age")
        if max_age and len(max_age) >= 2 and max_age[0] == max_age[-1] == '"':
            max_age = max_age[1:-1]
        if "includesubdomains" in directives and directives["includesubdomains"] is not None:
            malformed = True
        if malformed or max_age is None or not re.fullmatch(r"[0-9]+", max_age):
            add("hsts.invalid", "warning", "HSTS has duplicate directives or invalid required syntax.",
                "Use one max-age directive with a non-negative integer and valueless includeSubDomains.")
        elif not max_age.strip("0"):
            add("hsts.disabled", "warning", "HSTS max-age is zero; this removes the host's HSTS policy.",
                "Use a positive max-age if HTTPS enforcement is intended.")
        elif "includesubdomains" not in directives:
            add("hsts.subdomains", "info", "HSTS does not cover subdomains.",
                "Consider includeSubDomains only after verifying every affected subdomain supports HTTPS.")

    nosniff = response.values("x-content-type-options")
    if not nosniff:
        add("content_type.nosniff_missing", "warning", "X-Content-Type-Options: nosniff was not observed.",
            "Set nosniff and serve accurate Content-Type values.")
    elif len(nosniff) != 1 or nosniff[0].lower() != "nosniff":
        add("content_type.nosniff_invalid", "warning", "X-Content-Type-Options is ambiguous or not nosniff.",
            "Send a single X-Content-Type-Options header with value nosniff.")

    content_types = response.values("content-type")
    media_type = content_types[0].split(";", 1)[0].strip().lower() if content_types else ""
    if not content_types:
        add("content_type.missing", "info", "No Content-Type was observed; document classification depends on --document.",
            "Send an accurate Content-Type, or use --document for a known document response.")
    if document or media_type in {"text/html", "application/xhtml+xml"}:
        audit_document(response, add)
    audit_cookies(response, add, secure)
    return sorted(findings, key=lambda f: (-SEVERITY[f.severity], f.id, f.message))


def audit_document(response: Response, add) -> None:
    values = response.values("content-security-policy")
    policies, duplicate = parse_policies(values)
    if not values or all(not p for p in policies):
        add("csp.missing", "warning", "No non-empty enforcing Content-Security-Policy was observed.",
            "Design and test a CSP appropriate to this document; report-only policies do not enforce it.")
    if response.values("content-security-policy-report-only") and not values:
        add("csp.report_only", "info", "Only a report-only CSP was observed.",
            "Use reports to test a policy, then deploy an enforcing policy when ready.")
    if duplicate:
        add("csp.duplicate_directive", "info", "A CSP repeats a directive; its first occurrence is used.",
            "Remove duplicate directives to avoid misleading policy maintenance.")
    if policies:
        # Omnes regulae simul valent; una restrictio satis est ad actum vetandum.
        element_sources = [script_sources(p, element=True) for p in policies]
        eval_sources = [script_sources(p) for p in policies]

        def inline_allowed(sources: list[str] | None) -> bool:
            if sources is None:
                return True
            lowered = [s.lower() for s in sources]
            return "'unsafe-inline'" in lowered and "'strict-dynamic'" not in lowered and not any(NONCE_HASH.fullmatch(s) for s in sources)

        if all(inline_allowed(s) for s in element_sources):
            add("csp.inline_scripts", "warning", "The evaluated script source lists permit arbitrary inline script elements; other restrictions may still apply.",
                "Use a tested nonce or hash based script policy; avoid relying on unsafe-inline.")
        if all(s is None or "'unsafe-eval'" in [v.lower() for v in s] for s in eval_sources):
            add("csp.eval", "warning", "The evaluated script source lists do not restrict JavaScript string evaluation; other restrictions may still apply.",
                "Constrain script-src and remove unsafe-eval when the application can support it.")
        broad = {"*", "https:", "http:", "data:"}
        def broad_scripts(sources: list[str] | None) -> bool:
            if sources is None:
                return True
            lowered = {s.lower() for s in sources}
            if "'strict-dynamic'" in lowered:
                return False
            return bool(broad & lowered)
        if all(broad_scripts(s) for s in element_sources):
            add("csp.broad_scripts", "warning", "Every observed policy leaves script sources absent or broadly allowed.",
                "Review wildcard, scheme-wide, and data script sources; prefer narrowly scoped sources or nonce/hash policies.")

    framing = [p["frame-ancestors"] for p in policies if "frame-ancestors" in p]
    if framing:
        if all("*" in sources for sources in framing):
            add("framing.wildcard", "warning", "Every frame-ancestors directive includes a wildcard.",
                "Set an explicit embedding policy; enforcing frame-ancestors overrides X-Frame-Options in modern browsers.")
    else:
        xfo = response.values("x-frame-options")
        if not xfo:
            add("framing.missing", "warning", "Neither enforcing frame-ancestors nor X-Frame-Options was observed.",
                "If embedding is not intended, set CSP frame-ancestors 'none' or an appropriate allowlist.")
        elif len(xfo) != 1 or xfo[0].upper() not in {"DENY", "SAMEORIGIN"}:
            add("framing.invalid_xfo", "warning", "X-Frame-Options is conflicting or uses an unsupported value.",
                "Use a single DENY or SAMEORIGIN value, or a tested CSP frame-ancestors directive.")

    referrers = response.values("referrer-policy")
    known = {"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
             "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"}
    recognized = [v.strip().lower() for h in referrers for v in h.split(",") if v.strip().lower() in known]
    if not referrers:
        add("referrer.missing", "info", "No explicit Referrer-Policy was observed.",
            "Consider an explicit policy; current browser defaults already restrict cross-origin referrer detail.")
    elif not recognized:
        add("referrer.invalid", "warning", "Referrer-Policy has no recognized value.",
            "Send a supported Referrer-Policy value appropriate to the application's privacy needs.")
    elif recognized[-1] in {"unsafe-url", "no-referrer-when-downgrade"}:
        add("referrer.permissive", "warning", "The final recognized Referrer-Policy can send full paths and queries cross-origin.",
            "Consider strict-origin-when-cross-origin or a more restrictive policy.")


def audit_cookies(response: Response, add, secure: bool) -> None:
    """Attributa examinat; valores secretos numquam in relationem transfert."""
    for index, cookie in enumerate(response.values("set-cookie"), 1):
        parts = [part.strip() for part in cookie.split(";")]
        name, separator, _ = parts[0].partition("=")
        label = f"Cookie #{index}"
        if not separator or not TOKEN.fullmatch(name):
            add("cookie.malformed", "info", f"{label} has an invalid cookie name/value pair.",
                "Inspect the Set-Cookie syntax; cookie values are intentionally omitted from reports.")
            continue
        attrs: dict[str, str] = {}
        for item in parts[1:]:
            key, _, value = item.partition("=")
            attrs[key.lower()] = value.strip()
        if secure and "secure" not in attrs:
            add("cookie.secure_missing", "warning", f"{label} lacks the Secure attribute.",
                "Add Secure to cookies that should only travel over HTTPS.")
        if "httponly" not in attrs:
            add("cookie.httponly_missing", "info", f"{label} lacks HttpOnly; this can be intentional for script-readable cookies.",
                "Use HttpOnly for session cookies that client-side scripts do not need to read.")
        same_site = attrs.get("samesite", "").lower()
        if "samesite" not in attrs:
            add("cookie.samesite_missing", "info", f"{label} has no explicit SameSite attribute.",
                "Choose an explicit SameSite policy; browser defaults and cross-site requirements vary.")
        elif same_site not in {"strict", "lax", "none"}:
            add("cookie.samesite_invalid", "warning", f"{label} has an unrecognized SameSite value.",
                "Use Strict, Lax, or None according to the application's cross-site requirements.")
        elif same_site == "none" and "secure" not in attrs:
            add("cookie.samesite_none_insecure", "warning", f"{label} uses SameSite=None without Secure.",
                "Modern browsers require Secure for SameSite=None cookies.")
        if name.startswith("__Secure-") and (not secure or "secure" not in attrs):
            add("cookie.secure_prefix", "warning", f"{label} does not meet __Secure- prefix requirements.",
                "Set prefixed cookies from HTTPS with the Secure attribute.")
        if name.startswith("__Host-") and (not secure or "secure" not in attrs or attrs.get("path") != "/" or "domain" in attrs):
            add("cookie.host_prefix", "warning", f"{label} does not meet __Host- prefix requirements.",
                "Use HTTPS, Secure, Path=/, and no Domain attribute for __Host- cookies.")


def report(response: Response, findings: list[Finding], mode: str, history: list[dict] | None = None) -> dict:
    return {
        "schema_version": 1,
        "mode": mode,
        "target": display_url(response.url),
        "status": response.status,
        "redirects": history or [],
        "summary": {level: sum(f.severity == level for f in findings) for level in ("high", "warning", "info")},
        "findings": [asdict(f) for f in findings],
    }
