from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter
from pathlib import Path
from urllib.parse import quote

TOOL = 'vallum-http'
VERSION = "0.2.0"
LEVELS = {'info': 1, 'warning': 2, 'high': 3}
RULES = {'cookie.samesite_invalid', 'referrer.invalid', 'csp.duplicate_directive', 'csp.missing', 'hsts.disabled', 'framing.wildcard', 'content_type.missing', 'hsts.subdomains', 'csp.report_only', 'transport.http', 'response.error', 'hsts.missing', 'framing.invalid_xfo', 'hsts.invalid', 'csp.broad_scripts', 'referrer.missing', 'redirect.cross_host', 'content_type.nosniff_invalid', 'content_type.nosniff_missing', 'redirect.limit', 'hsts.multiple', 'cookie.httponly_missing', 'redirect.downgrade', 'referrer.permissive', 'csp.eval', 'framing.missing', 'cookie.secure_prefix', 'cookie.host_prefix', 'hsts.insecure', 'redirect.invalid_location', 'cookie.malformed', 'cookie.secure_missing', 'response.redirect', 'transport.http_hop', 'redirect.loop', 'cookie.samesite_none_insecure', 'csp.inline_scripts', 'hsts.ip_literal', 'cookie.samesite_missing'}
MAX_BASELINE_BYTES = 1_048_576


class BaselineError(ValueError):
    pass


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BaselineError("Baseline contains duplicate keys.")
        result[key] = value
    return result


def label_value(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value):
        raise BaselineError("Baseline label must be a public identifier of 1 to 64 letters, digits, hyphens or underscores.")
    return value


def artifact_value(value):
    if not isinstance(value, str) or len(value) > 240 or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./-]*", value):
        raise BaselineError("SARIF artifact must be an explicitly public repository-relative path.")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise BaselineError("SARIF artifact must not contain empty or relative traversal segments.")
    return value


def _scope(value):
    return "response"


def snapshot(findings, label):
    """Indices mobiles excludit; genera et numeri tantum servantur."""
    groups = Counter((f["id"], _scope(f), f["severity"]) for f in findings)
    if sum(groups.values()) > 100000 or len(groups) > 10000:
        raise BaselineError("Finding counts exceed the supported snapshot limit.")
    return {
        "schema_version": 1, "tool": TOOL, "tool_version": VERSION,
        "label": label_value(label), "comparison_scope": "aggregate-rule-scope",
        "findings": [{"rule_id": rule, "scope": scope, "severity": severity, "count": count}
                     for (rule, scope, severity), count in sorted(groups.items())],
    }


def load_baseline(data, label):
    """Relationem alienam stricte probat nec eius verba repetit."""
    try:
        if len(data) > MAX_BASELINE_BYTES:
            raise ValueError()
        value = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value, dict) or set(value) != {"schema_version", "tool", "tool_version", "label", "comparison_scope", "findings"}:
            raise ValueError()
        if type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["tool"] != TOOL:
            raise ValueError()
        if not isinstance(value["tool_version"], str) or not re.fullmatch(r"0\.2\.[0-9]+", value["tool_version"]):
            raise ValueError()
        if value["comparison_scope"] != "aggregate-rule-scope" or label_value(value["label"]) != label_value(label):
            raise ValueError()
        findings = value["findings"]
        if not isinstance(findings, list) or len(findings) > 10000:
            raise ValueError()
        seen = set()
        total = 0
        for item in findings:
            if not isinstance(item, dict) or set(item) != {"rule_id", "scope", "severity", "count"}:
                raise ValueError()
            rule, scope, severity = item["rule_id"], item["scope"], item["severity"]
            if not isinstance(rule, str) or rule not in RULES or not isinstance(severity, str) or severity not in LEVELS:
                raise ValueError()
            if not isinstance(scope, str) or not re.fullmatch('response', scope):
                raise ValueError()
            if type(item["count"]) is not int or not 1 <= item["count"] <= 100000:
                raise ValueError()
            key = rule, scope, severity
            if key in seen:
                raise ValueError()
            seen.add(key)
            total += item["count"]
        if total > 100000:
            raise ValueError()
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise BaselineError("Invalid or incompatible baseline; expected this tool's schema 1, version 0.2, matching label and bounded finding counts.") from None


def compare(current, previous):
    """Paria ordinum non fingit; mutationes gregum exponit."""
    before = {(f["rule_id"], f["scope"], f["severity"]): f["count"] for f in previous["findings"]}
    after = {(f["rule_id"], f["scope"], f["severity"]): f["count"] for f in current["findings"]}
    result = {"scope": "aggregate-rule-scope", "added": [], "resolved": [], "unchanged": [], "severity_changed": []}
    for rule, scope in sorted({key[:2] for key in before} | {key[:2] for key in after}):
        old, new = {}, {}
        for severity in LEVELS:
            a, b = before.get((rule, scope, severity), 0), after.get((rule, scope, severity), 0)
            common = min(a, b)
            if common:
                result["unchanged"].append({"rule_id": rule, "scope": scope, "severity": severity, "count": common})
            old[severity], new[severity] = a - common, b - common
        for source in LEVELS:
            for target in LEVELS:
                count = min(old[source], new[target])
                if count:
                    result["severity_changed"].append({"rule_id": rule, "scope": scope, "from": source, "to": target, "count": count})
                    old[source] -= count
                    new[target] -= count
        for severity in LEVELS:
            for key, remaining in (("resolved", old), ("added", new)):
                if remaining[severity]:
                    result[key].append({"rule_id": rule, "scope": scope, "severity": severity, "count": remaining[severity]})
    result["summary"] = {key: sum(item["count"] for item in result[key]) for key in ("added", "resolved", "unchanged", "severity_changed")}
    return result


def fail_new(comparison, threshold):
    if threshold not in LEVELS:
        return False
    return any(LEVELS[f["severity"]] >= LEVELS[threshold] for f in comparison["added"]) or any(
        LEVELS[f["to"]] > LEVELS[f["from"]] and LEVELS[f["to"]] >= LEVELS[threshold]
        for f in comparison["severity_changed"])


def _file_signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_baseline(path, label):
    """Fistulae et nexus reiciuntur; lectio finita stabilitatem requirit."""
    try:
        expected = os.lstat(path)
        if not stat.S_ISREG(expected.st_mode):
            raise BaselineError("Baseline must be a regular file, not a symbolic link or special file.")
        if expected.st_size > MAX_BASELINE_BYTES:
            raise BaselineError("Baseline exceeds the supported byte limit.")
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode) or _file_signature(expected) != _file_signature(before):
                raise BaselineError("Baseline changed before it could be read.")
            data = handle.read(MAX_BASELINE_BYTES + 1)
            after, current = os.fstat(handle.fileno()), os.lstat(path)
            if _file_signature(before) != _file_signature(after) or _file_signature(after) != _file_signature(current):
                raise BaselineError("Baseline changed while being read.")
        return load_baseline(data, label)
    except OSError:
        raise BaselineError("Baseline could not be read; path and system details withheld.") from None


def write_baseline(path, value):
    """Exemplar vetus non delet; destinatio nova esse debet."""
    try:
        with Path(path).open("x", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError:
        raise BaselineError("Baseline could not be created; choose a new writable destination. Existing files are never overwritten.") from None


def sarif(findings, errors=(), comparison=None, artifact=None):
    """SARIF sine capitibus, secretis aut viis privatis construit."""
    artifact = artifact_value(artifact or "vallum-report.json")
    grouped = Counter((f["id"], _scope(f), f["severity"]) for f in findings)
    groups = [{"rule_id": rule, "scope": scope, "severity": severity, "count": count}
              for (rule, scope, severity), count in sorted(grouped.items())]
    rules = sorted({f["rule_id"] for f in groups})
    by_rule = {rule: next(f for f in findings if f["id"] == rule) for rule in rules}
    results = []
    for group in groups:
        rule, scope, severity = group["rule_id"], group["scope"], group["severity"]
        finding = by_rule[rule]
        key = f"{TOOL}|{rule}|{scope}|{severity}"
        item = {
            "ruleId": rule, "ruleIndex": rules.index(rule),
            "level": {'info': 'note', 'warning': 'warning', 'high': 'error'}[severity],
            "message": {"text": f"{group['count']} observation(s) in {scope}. " + re.sub(r"Cookie #[0-9]+", "A cookie", finding["message"])},
            "partialFingerprints": {"ruleScope/v1": hashlib.sha256(key.encode()).hexdigest(),
                                    "primaryLocationLineHash": hashlib.sha256(key.encode()).hexdigest()},
            "properties": {"severity": severity, "count": group["count"], "scope": scope},
            "locations": [{"logicalLocations": [{"fullyQualifiedName": scope, "kind": "module"}]}],
        }
        if artifact is not None:
            item["locations"][0]["physicalLocation"] = {"artifactLocation": {"uri": quote(artifact_value(artifact), safe="/._-"), "uriBaseId": "%SRCROOT%"}, "region": {"startLine": 1}}
        results.append(item)
    run = {"tool": {"driver": {"name": TOOL, "semanticVersion": VERSION,
             "informationUri": f"https://github.com/artifexignotvs/{TOOL}",
             "rules": [{"id": rule, "shortDescription": {"text": re.sub(r"Cookie #[0-9]+", "A cookie", by_rule[rule]["message"])[:1024]},
                        "help": {"text": by_rule[rule]["recommendation"]}} for rule in rules]}},
           "automationDetails": {"id": TOOL + "/"}, "results": results,
           "invocations": [{"executionSuccessful": not bool(errors)}]}
    if artifact is not None:
        run["originalUriBaseIds"] = {"%SRCROOT%": {"uri": "file:///source/"}}
    if errors:
        run["invocations"][0]["toolExecutionNotifications"] = [{"level": "error", "message": {"text": "Audit did not complete; input or baseline validation failed."}}]
    if comparison is not None:
        run["properties"] = {"comparison": comparison}
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [run]}
