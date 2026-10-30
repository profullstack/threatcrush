#!/usr/bin/env python3
"""Redacted CI reporting and account policy. No snippets or messages are sent.

Copy to .github/threatcrush-report.py and invoke after the scan, before SARIF
upload. Requires SCAN_STATUS, GITHUB_REPOSITORY, GITHUB_RUN_ID, RUNNER_TEMP.
THREATCRUSH_REPO_TOKEN is optional; forks never receive that Actions secret.
"""
import hashlib
import json
import os
import re
import sys
from pathlib import Path
import urllib.error
import urllib.request

SEVERITIES = ("critical", "high", "medium", "low", "info")
ENDPOINT = "https://threatcrush.com/api/github/repositories/report"
SETTINGS = "https://threatcrush.com/account#repository-alerts"


def severity(result, rules):
    value = result.get("properties", {}).get("severity")
    # Explicit critical metadata must never be reduced to a generic warning.
    if value in SEVERITIES:
        return value
    score = rules.get(result.get("ruleId"), {}).get("properties", {}).get("security-severity")
    try:
        if float(score) >= 9:
            return "critical"
    except (ValueError, TypeError):
        pass
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(result.get("level"), "medium")


def verified_pem_placeholder(file, line, root):
    """A named dummy PEM body is evidence; a test/example path alone is not."""
    try:
        base = Path(root).resolve()
        path = (base / file).resolve()
        if not path.is_relative_to(base) or not path.is_file():
            return False
        with path.open(encoding="utf8", errors="replace") as handle:
            text = handle.read(262145)
        if len(text) > 262144:
            return False
        lines = text.splitlines()
        first = lines[line - 1]
        header = re.search(r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?)-----", first)
        if not header:
            return False
        tail = "\n".join([first[header.end():]] + lines[line:line + 20]).replace("\\n", "\n")
        footer = "-----END " + header.group(1) + "-----"
        end = tail.find(footer)
        if end < 0:
            return False
        # Exact, known dummy bodies only. A base64 body, a missing footer, or
        # any extra material stays critical even inside an example file.
        return tail[:end].strip().lower() in ("your-pem-body-here", "your-private-key-here", "your-private-key-body-here")
    except (OSError, IndexError, ValueError):
        return False


def metadata(result, rules, source_root="."):
    physical = result["locations"][0]["physicalLocation"]
    file = physical["artifactLocation"]["uri"]
    rule = result["ruleId"]
    # Hash snippets locally for stable deduplication; never transmit them.
    snippet = physical.get("region", {}).get("snippet", {}).get("text", "")
    content = re.sub(r"\s+", " ", snippet).strip()
    fingerprint = result.get("partialFingerprints", {}).get("threatcrush/contentHash/v1")
    if not fingerprint:
        fingerprint = hashlib.sha256(f"{rule}\n{file}\n{content}".encode()).hexdigest()[:32]
    line = max(1, physical.get("region", {}).get("startLine", 1))
    detected = severity(result, rules)
    if rule == "secret-private-key" and detected == "critical" and verified_pem_placeholder(file, line, source_root):
        detected = "low"
        result.setdefault("properties", {}).update({"severity": "low", "originalSeverity": "critical", "classification": "verified-placeholder"})
        result["message"] = {"text": "Private-key example contains an explicit placeholder body, not key material"}
    return {"ruleId": rule, "file": file, "line": line, "severity": detected, "fingerprint": fingerprint}


def example(file):
    return bool(re.search(r"(?:^|/)(?:tests?|__tests__|__mocks__|specs?|fixtures?|mocks?|e2e|testdata|testutils?|harness|docs?|examples?|samples?|demo)(?:/|$)|[._-](?:test|spec)\.[a-z]+$|(?:^|/)(?:test|conftest)_[^/]+$|(?:^|/)\.env\.(?:example|sample|template)(?:\.|$)|(?:^|/)(?:example|sample)\.env$|(?:^|/)readme(?:\.[^/]*)?$", file.replace("\\", "/"), re.I))


def report(log, env, submit=None):
    lines = ["## ThreatCrush Security Scan", ""]
    if env.get("SCAN_STATUS") not in ("clean", "findings"):
        return lines + ["**NOT RUN** — the scan did not complete. See the job log."], False
    results, metas = [], []
    for run in log["runs"]:
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for r in run["results"]:
            results.append(r)
            metas.append(metadata(r, rules, env.get("GITHUB_WORKSPACE", ".")))
    visible, failed, connected = list(range(len(results))), False, False
    if env.get("THREATCRUSH_REPO_TOKEN"):
        try:
            payload = {"repository": env["GITHUB_REPOSITORY"], "run_id": env["GITHUB_RUN_ID"], "findings": metas}
            policy = (submit or post)(payload, env["THREATCRUSH_REPO_TOKEN"])
            indexes = policy["visible"]
            if not isinstance(indexes, list) or any(type(i) is not int or i < 0 or i >= len(results) for i in indexes):
                raise ValueError("Invalid policy response")
            if any(m["severity"] == "critical" and i not in indexes for i, m in enumerate(metas)):
                raise ValueError("Policy attempted to silence critical finding")
            visible, connected = indexes, True
        except Exception:
            # Do not print exceptions: HTTP bodies can echo request credentials.
            lines += ["**Repository connection failed.** All local warnings remain visible. Critical paging could not be confirmed; rerun this job.", ""]
            failed = True
    else:
        lines += ["Local report — repository account settings and team paging are not connected for this run.", ""]
    critical = sum(m["severity"] == "critical" for m in metas)
    warnings = sum(metas[i]["severity"] != "critical" for i in visible)
    lines += [f"**CRITICAL**: {critical} | **Warnings**: {warnings} | **Silenced warnings**: {len(results) - len(visible)}", ""]
    if critical:
        lines += ["Critical findings remain visible regardless of warning silences." + (" A deduplicated incident routes pages to your assigned team using its notification settings." if connected else " Connect this repository to enable team incident paging."), ""]
    if visible:
        lines += ["| Level | Detected severity | Rule | Location |", "|---|---|---|---|"]
        ordered = sorted(visible, key=lambda i: (metas[i]["severity"] != "critical", i))
        for i in ordered[:50]:
            m = metas[i]
            path = m["file"].replace("|", "\\|").replace("`", "'").replace("\n", " ").replace("\r", " ")
            label = "CRITICAL" if m["severity"] == "critical" else "WARNING"
            context = " (test/example)" if example(m["file"]) else ""
            lines.append(f"| {label}{context} | {m['severity'].upper()} | `{m['ruleId']}` | `{path}`:{m['line']} |")
        if len(visible) > 50:
            lines += ["", f"_…and {len(visible) - 50} more visible findings. Full results are in the SARIF artifact._"]
    elif not results:
        lines.append("No findings.")
    else:
        lines.append("All noncritical warnings are silenced by your repository policy. This is not a zero-finding scan.")
    for i, result in enumerate(results):
        # Keep exact severity metadata, while the annotation level makes clear
        # that noncritical matches require triage rather than being errors.
        result["level"] = "error" if metas[i]["severity"] == "critical" else "warning"
        if i not in visible:
            result["suppressions"] = [{"kind": "external", "status": "accepted", "justification": "Silenced by repository warning settings in ThreatCrush account"}]
    lines += ["", f"[Manage repository warnings and critical paging]({SETTINGS}).", "", "Source snippets and credential material are never sent to the account service or printed in this report."]
    return lines, failed


def post(payload, token):
    req = urllib.request.Request(ENDPOINT, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"}, method="POST")
    # Refuse redirects so credentials cannot travel to another host.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    with urllib.request.build_opener(NoRedirect).open(req, timeout=90) as res:
        return json.load(res)


def main():
    failed = False
    try:
        with open("threatcrush.sarif") as f:
            log = json.load(f)
        lines, failed = report(log, os.environ)
        with open("threatcrush.sarif", "w") as f:
            json.dump(log, f)
    except Exception:
        lines = ["## ThreatCrush Security Scan", "", "**REPORT FAILED** — scan results could not be read; check the job log. Critical paging could not be confirmed."]
        failed = True
    with open(os.path.join(os.environ["RUNNER_TEMP"], "threatcrush-comment.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
