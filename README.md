# VALLUM HTTP

**One response. Clear findings. No runtime dependencies.**

A small HTTP security-header auditor for developers, infrastructure maintainers, and CI. Review a saved response without making a network request, or inspect one explicitly selected URL. Get stable finding IDs, actionable explanations, and deterministic JSON instead of a misleading security score.

Python 3.10+ · MIT · Standard library only

## Try it in 20 seconds

From the repository directory:

```sh
python3 -m vallum_http \
  --headers examples/hardened.headers \
  --origin https://demo.invalid/
```

```text
VALLUM HTTP  https://demo.invalid/
HTTP 200 | offline | 0 high, 0 warning, 0 info
No findings in the implemented checks. This is not a security certification.
```

Compare a response that needs attention:

```sh
python3 -m vallum_http \
  --headers examples/needs-review.headers \
  --origin https://demo.invalid/ \
  --fail-on none
```

Example finding:

```text
[WARNING] cookie.samesite_none_insecure: Cookie #1 uses SameSite=None without Secure.
  Next: Modern browsers require Secure for SameSite=None cookies.
```

Both examples run entirely offline. The example domain is intentionally not a live target. The hardened fixture demonstrates these checks; its policy is not a universal configuration to paste into production.

## Install, if wanted

Running from the checkout needs no installation. To add a terminal command in a virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
vallum-http --version
```

The build uses setuptools. The installed application has no third-party runtime dependencies. On Windows, activate the environment with `.venv\Scripts\activate`.

## Inspect a response

### Saved headers

```sh
python3 -m vallum_http \
  --headers response.headers \
  --origin https://your-host.example/account \
  --format json
```

`--origin` must be the URL that delivered the final saved response. It determines whether HTTPS-only checks apply; offline mode cannot verify that the file came from that URL or that its certificate was valid.

Input is UTF-8 header text, with an optional HTTP status line. Repeated fields remain separate. For a header dump containing several response blocks, the final block is inspected. Provide the final response URL as `--origin`; earlier saved blocks are not audited as a redirect chain. Files over 1 MiB, bodies, folded headers, malformed fields, and final informational responses are rejected. Without a status line, HTTP 200 is assumed. Use `--headers -` to read standard input.

### One explicit URL

```sh
python3 -m vallum_http --url https://your-host.example/
```

The default makes one `HEAD` request. No crawling, discovery, login, cookie storage, or automatic retries. TLS certificate and hostname verification remain enabled; there is no insecure switch. Environment proxy settings are ignored.

URLs accept DNS hostnames, IPv4 addresses, and bracketed IPv6 addresses. Unicode hostnames are normalized with IDNA, and Unicode paths and queries are percent-encoded. Credentials, IPv6 zone identifiers, ambiguous authorities, raw backslashes, and malformed percent escapes are rejected.

Some applications return different headers to `HEAD` than `GET`. Select GET explicitly when needed:

```sh
python3 -m vallum_http \
  --url https://your-host.example/ \
  --method GET \
  --max-redirects 2 \
  --timeout 5
```

Response bodies are not read, including after GET. The server still receives the request and can perform application-specific work. Use online mode only for endpoints you are permitted to inspect.

Redirects are not followed by default. `--max-redirects N` permits up to N additional requests, from 0 through 5. Only redirects to the original hostname are followed; ports may differ. HTTPS-to-HTTP redirects are always blocked. An initial HTTP hop remains a high-severity finding even when the final response uses HTTPS. Cookies are never replayed between requests. Redirect responses are recorded, but only the final inspected response receives the full header audit.

The timeout is a per-request socket timeout, from 0.1 through 60 seconds. It is not a total wall-clock deadline and does not guarantee a bound on operating-system DNS resolution. Response header size is checked against 1 MiB after the standard library parses it; the standard library also imposes its own line/count limits.

## What it checks

| Area | Checks and interpretation |
| --- | --- |
| Transport | Unencrypted final response or followed hop; redirects to HTTP; redirect loops and bounds |
| HSTS | Presence on HTTPS, basic directive syntax, duplicate directives, zero max-age, optional subdomain coverage; first field wins; IP literals are called out |
| CSP | Missing or report-only policy; duplicate directives; broad script sources; inline script elements and string evaluation permitted by the evaluated source lists |
| Framing | Enforcing `frame-ancestors` takes precedence over X-Frame-Options; `default-src` is not a framing fallback; wildcard and invalid XFO checks |
| MIME | Missing or ambiguous `nosniff`, missing Content-Type |
| Referrer | Last recognized policy value, permissive cross-origin path/query disclosure, invalid policy |
| Cookies | Secure, HttpOnly, SameSite; `SameSite=None` without Secure; `__Secure-` and `__Host-` requirements |

CSP, framing, and referrer checks run on `text/html` and `application/xhtml+xml` responses. Use `--document` when a response is known to be a document but its media type does not identify it. An API returning JSON is not automatically marked down for missing document policies.

Missing HttpOnly and SameSite are informational because intended script access and browser defaults matter. Missing HSTS on HTTPS is a warning; missing `includeSubDomains` is informational because enabling it can break unrelated hosts. A missing explicit referrer policy is informational because modern browser defaults already provide protection.

## CI and structured output

```sh
python3 -m vallum_http \
  --headers response.headers \
  --origin https://your-host.example/ \
  --format json \
  --fail-on warning > report.json
```

| Exit | Meaning |
| --- | --- |
| `0` | No finding meets the selected threshold |
| `1` | At least one finding meets the selected threshold |
| `2` | Input, usage, transport, or parsing error; no completed audit |

`--fail-on` accepts `info`, `warning` (default), `high`, or `none`. Changing the threshold changes the exit code, not the findings. Network and file errors return a JSON error object when `--format json` is selected. Argument syntax errors use the command parser's standard error output.

Successful JSON contains `schema_version`, `mode`, `target`, `status`, `redirects`, `summary`, and `findings`. Each finding has `id`, `severity`, `message`, and `recommendation`. IDs are intended for automation; message wording can improve between releases. Findings are sorted by severity, ID, then message. The schema is versioned; finding IDs are stable within the 0.2 release line.

Cookie names and values, raw headers, URL queries, and fragments are omitted from successful reports. Hostnames and paths remain, and paths can contain secrets. Review reports before sharing them. Runtime URL, encoding, filesystem, and transport errors use messages that omit raw exception details. Argument syntax errors use the standard argument parser and may repeat supplied arguments.


## New in 0.2: policy finding snapshots and SARIF

Capture a reviewed baseline and gate later changes:

```sh
python3 -m vallum_http --headers examples/needs-review.headers \
  --origin https://demo.invalid/ --write-baseline baseline.json \
  --baseline-label public-document --fail-on none
python3 -m vallum_http --headers examples/needs-review.headers \
  --origin https://demo.invalid/ --baseline baseline.json \
  --baseline-label public-document --fail-on-new --format json
```

Unchanged findings exit `0` in the second command. `--fail-on-new` fails only for added findings or severity increases meeting the selected `--fail-on` threshold. Resolutions and severity decreases do not fail it; `--fail-on none` disables finding failures. Without the new flag, the original full-report threshold is unchanged. Invalid baselines and other input errors exit `2`. Baseline writes require a new destination and never overwrite existing files. The tool validates a supplied baseline before making an online request.

This is a **difference between observed policy findings**, not proof that a vulnerability appeared or was fixed. Snapshots intentionally contain no raw headers, cookie names or values, URLs, queries, hostname/path data, or secret hashes. Counts are aggregated by rule and severity across the response. Cookie order changes do not create false identity matches. Moving a missing attribute between two cookies while preserving counts is invisible; changing a policy to another value that yields the same findings is also invisible. Use direct header review when exact policy differences matter.

Provide the same public `--baseline-label` for the same endpoint, request method, authentication context, document classification and capture procedure. Labels are opaque letters/digits/hyphens/underscores, not URLs. They do not verify endpoint identity or comparable collection conditions. Do not compare different endpoints or HEAD/GET observations under one label. This deliberate privacy tradeoff avoids storing target identifiers. Baseline changes should be reviewed, not accepted automatically.

Successful JSON keeps `schema_version: 1` and its original fields. With `--baseline`, the added `comparison` object has `scope: "aggregate-rule-scope"`; `added`, `resolved`, `unchanged`, and `severity_changed` arrays; and summary observation counts. Entries use `rule_id`, `scope: "response"`, `severity`, `count`. Severity shifts use `from` and `to` instead of `severity`. Equal severity counts are cancelled first, then remaining counts are paired in ascending severity order. These are aggregate shifts, not proof that the same cookie changed severity.

A ready-made synthetic snapshot is included at `examples/review.baseline.json`, labeled `synthetic-example`.

The separate baseline schema contains exactly `schema_version: 1`, `tool: "vallum-http"`, `tool_version`, `label`, `comparison_scope: "aggregate-rule-scope"`, and grouped `findings`. It is not the ordinary JSON report. Only version 0.2 snapshots are accepted. Unknown fields/rules, duplicate keys/groups, incompatible versions, wrong labels, invalid counts and oversized data fail closed. Limits are 1 MiB, 10,000 groups and 100,000 total observations. Existing JSON/text reports retain their documented hostname/path visibility; the new snapshots and SARIF omit it.

### SARIF 2.1.0

```sh
python3 -m vallum_http --headers examples/needs-review.headers \
  --origin https://demo.invalid/ --format json --fail-on none > vallum-report.json
python3 -m vallum_http --headers examples/needs-review.headers \
  --origin https://demo.invalid/ --format sarif \
  --sarif-artifact vallum-report.json --fail-on none > vallum.sarif
```

Review the ordinary report before publishing it: it can contain hostnames and paths. SARIF itself contains grouped findings, rule help, severity levels and execution status, with no raw response or target identifiers. Its default artifact is the public name `vallum-report.json`; line 1 is a summary anchor, not a claim to locate a source-code defect. `--sarif-artifact` accepts only an explicitly public repository-relative path. Generate that reviewed report in the checkout before code-scanning upload. The synthetic `%SRCROOT%` URI is `file:///source/`; consumers requiring an absolute checkout URI should map it to their checkout. Upload permissions/service availability remain the user's responsibility. Full schema validation is tested; live service ingestion has not been tested.

Fingerprints derive from public rule/scope/severity only and inherit aggregate identity limits. No numeric vulnerability score is assigned. An audit or baseline error emits valid SARIF with unsuccessful execution, a generic diagnostic and exit `2`.

Format references: [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html) and [code-scanning SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).

## Boundaries

Vallum HTTP is a response-configuration review tool, not a vulnerability scanner or a browser. It does not inspect page bodies, execute scripts, exploit endpoints, verify authentication, assess cookie sensitivity, test CSRF defenses, audit certificates beyond normal TLS verification, or establish whether an application is secure.

CSP checks are deliberately limited source-list heuristics for modern implementations. Multiple policies are considered as simultaneous restrictions for the implemented script and framing checks. Nonce/hash syntax and `strict-dynamic` affect those heuristics, but the tool does not assess nonce randomness or reuse, validate every directive/source expression, emulate browser versions, inspect script event handlers, or prove a policy cannot be bypassed. Sandbox directives and other browser-context restrictions are not evaluated, so a permissive source-list finding does not prove a script will execute. `frame-ancestors` presence is not full syntax validation. Review the actual policy and application behavior.

Existing browser HSTS state, preloading, HTML meta policies, service workers, authenticated responses, CDN variations, and browser-specific behavior are outside the snapshot. Redirect response cookie/header policies are not part of the final-response audit. An endpoint can intentionally return different content to this client. A zero-finding result means only that these checks did not flag the observed input.

The URL client is a local command-line utility. Do not expose it directly as a service accepting untrusted URLs: it permits explicitly supplied private and loopback destinations, and it is not an SSRF isolation boundary.

## Development

```sh
python3 -m unittest discover -s tests -v
```

The suite covers parser rejection, policy interactions, redaction, CLI exit behavior, mocked TLS/redirect handling, and real HTTP requests to an ephemeral loopback server. Tests do not contact external endpoints. Explanatory comments and docstrings use Latin; public help and documentation use English.

Contributions should include a minimal header fixture and a regression test for behavioral changes. Keep the runtime dependency-free and prefer a narrow, explainable finding to an unsupported security claim.

## References

- [HSTS: RFC 6797](https://www.rfc-editor.org/rfc/rfc6797)
- [Content Security Policy Level 3](https://www.w3.org/TR/CSP/)
- [Referrer Policy](https://www.w3.org/TR/referrer-policy/)
- [HTTP cookies: RFC 6265](https://www.rfc-editor.org/rfc/rfc6265)
- [HTTP State Management Mechanism revision](https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html)

## License

MIT. See [LICENSE](LICENSE).
