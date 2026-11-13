"""Report formats for CI systems: SARIF 2.1.0 (GitHub code scanning), GitHub annotations, Markdown summary."""
from collections import Counter
from importlib.metadata import PackageNotFoundError, version
import os
from pathlib import Path
import re

from .static import RULES

REPO_URL = "https://github.com/Subhagatoadak/ThreatDocket"
SECURITY_SEVERITY = {"high": "8.0", "medium": "5.5", "low": "3.0"}
LEVEL = {"FAIL": "error", "REVIEW": "warning"}
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]")


def _clean(value):
    return CONTROL_CHARS.sub("", str(value))


def _version():
    try:
        return version("threatdocket")
    except PackageNotFoundError:
        return "0.0.0"


def _technique_url(technique):
    return f"https://atlas.mitre.org/techniques/{technique}"


def repo_path(project, relative, base=None):
    """Path of a finding relative to the repository root (GITHUB_WORKSPACE or the working directory)."""
    base = Path(base or os.getenv("GITHUB_WORKSPACE") or Path.cwd()).resolve()
    full = (Path(project).resolve() / relative)
    try:
        return full.relative_to(base).as_posix()
    except ValueError:
        return Path(relative).as_posix()


def to_sarif(report, project, base=None):
    rule_ids = sorted(RULES)
    rules = []
    for rule_id in rule_ids:
        severity, status, title, technique, action = RULES[rule_id]
        rules.append({
            "id": rule_id,
            "name": re.sub(r"[^A-Za-z0-9]+", "", title.title()),
            "shortDescription": {"text": title},
            "fullDescription": {"text": f"{title}. Mapped to MITRE ATLAS {technique}."},
            "helpUri": _technique_url(technique),
            "help": {
                "text": f"{action}\nMITRE ATLAS: {technique}",
                "markdown": f"**Recommended action:** {action}\n\n"
                            f"**MITRE ATLAS:** [{technique}]({_technique_url(technique)})\n\n"
                            f"**Status when matched:** `{status}` "
                            f"({'policy match' if status == 'FAIL' else 'needs human verification'})",
            },
            "defaultConfiguration": {"level": LEVEL[status]},
            "properties": {
                "tags": ["security", "ai-security", "mitre-atlas", technique],
                "security-severity": SECURITY_SEVERITY.get(severity, "5.0"),
                "precision": "high" if status == "FAIL" else "medium",
            },
        })
    results = []
    for item in report["findings"]:
        if item["rule"] not in RULES:
            continue
        results.append({
            "ruleId": item["rule"],
            "ruleIndex": rule_ids.index(item["rule"]),
            "level": LEVEL.get(item["status"], "warning"),
            "message": {"text": f"{item['title']}. {item['action']} (MITRE ATLAS {item['technique']})"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": repo_path(project, item["path"], base), "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": item["line"] or 1},
            }}],
            "properties": {"status": item["status"], "atlas_cases": item.get("cases", [])[:10]},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "ThreatDocket",
                "informationUri": REPO_URL,
                "semanticVersion": _version(),
                "version": _version(),
                "rules": rules,
            }},
            "automationDetails": {"id": "threatdocket/"},
            "results": results,
            "properties": {"atlas_version": report["atlas_version"], "warnings": report["warnings"]},
        }],
    }


def _escape_data(value):
    return _clean(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value):
    return _escape_data(value).replace(":", "%3A").replace(",", "%2C")


def annotations(report, project, base=None):
    """GitHub Actions workflow commands that show findings inline on the PR and the Checks page."""
    lines = []
    for item in report["findings"]:
        kind = "error" if item["status"] == "FAIL" else "warning"
        props = [f"file={_escape_property(repo_path(project, item['path'], base))}"]
        if item["line"]:
            props.append(f"line={item['line']}")
        props.append(f"title={_escape_property('ThreatDocket ' + item['rule'] + ': ' + item['title'])}")
        message = f"{item['action']} (MITRE ATLAS {item['technique']}; status {item['status']})"
        lines.append(f"::{kind} {','.join(props)}::{_escape_data(message)}")
    for row in report["controls"]:
        if row["status"] == "ATTESTED_FAIL":
            lines.append(f"::error title={_escape_property('ThreatDocket control ' + row['id'])}::"
                         f"{_escape_data(row['title'] + ' — attested as failing')}")
    for warning in report["warnings"]:
        lines.append(f"::notice title=ThreatDocket scan scope::{_escape_data(warning)}")
    return lines


def _cell(value):
    return _clean(value).replace("|", "\\|").replace("`", "'").replace("<", "&lt;").replace("\n", " ")


def markdown_summary(report, project, base=None, limit=100):
    findings = report["findings"]
    counts = report["summary"]["findings"]
    controls = report["summary"]["controls"]
    fails = counts.get("FAIL", 0)
    reviews = counts.get("REVIEW", 0)
    icon = "❌" if fails or controls.get("ATTESTED_FAIL") else ("⚠️" if reviews else "✅")
    out = [f"## {icon} ThreatDocket scan", ""]
    out.append(f"**{fails}** FAIL · **{reviews}** REVIEW · {report['files_examined']} files examined · "
               f"MITRE ATLAS {report['atlas_version']}")
    out.append("")
    if findings:
        out += ["| Status | Severity | Rule | Finding | Location |", "| --- | --- | --- | --- | --- |"]
        order = {"FAIL": 0, "REVIEW": 1}
        for item in sorted(findings, key=lambda f: (order.get(f["status"], 2), f["path"], f["line"] or 0))[:limit]:
            where = repo_path(project, item["path"], base) + (f":{item['line']}" if item["line"] else "")
            out.append(f"| {'🔴 FAIL' if item['status'] == 'FAIL' else '🟡 REVIEW'} | {item['severity']} | "
                       f"{item['rule']} | {_cell(item['title'])} | `{_cell(where)}` |")
        if len(findings) > limit:
            out.append(f"\n_{len(findings) - limit} more findings in the SARIF/JSON report._")
        out.append("")
        out.append("<details><summary>Recommended actions</summary>\n")
        for rule, count in sorted(Counter(f["rule"] for f in findings).items()):
            out.append(f"- **{rule}** ({count}): {_cell(RULES[rule][4])}")
        out.append("\n</details>")
    else:
        out.append("No static rule matched the files examined.")
    out += ["", "**Controls:** " + (", ".join(f"{k} {v}" for k, v in sorted(controls.items())) or "none")]
    if report["warnings"]:
        out += ["", "**Scan limitations:** " + "; ".join(_cell(w) for w in report["warnings"])]
    return "\n".join(out) + "\n"
