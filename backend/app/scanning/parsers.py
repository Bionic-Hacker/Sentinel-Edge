"""Reduce each scanner's JSON report to normalised findings.

One function per report format, plus `load_reports`, which reads a directory written by
`scripts/scan.sh` and dispatches on the file name. Paths are made relative to the repository
root (scanners in containers report /src/... or /repo/...), so the same issue gets the same
fingerprint whichever machine ran the scan.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.scanning.findings import Finding, fingerprint

CONTAINER_ROOTS = ("/src/", "/repo/", "/project/", "/zap/wrk/")

_SEMGREP_LEVEL = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
_BANDIT_LEVEL = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_TRIVY_LEVEL = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "medium",
}
_CHECKOV_LEVEL = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
}
_ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
_SEVERITY_WORDS = frozenset({"critical", "high", "medium", "low", "info"})


def relative_path(path: str, root: Path | None = None) -> str:
    """Repository-relative path for a scanner-reported path."""
    for prefix in CONTAINER_ROOTS:
        if path.startswith(prefix):
            return path[len(prefix) :]
    if root is not None:
        try:
            return str(Path(path).resolve().relative_to(root.resolve()))
        except ValueError:
            pass
    return path[2:] if path.startswith("./") else path.lstrip("/")


def _source_line(root: Path | None, path: str, line: int) -> str | None:
    """The stripped text of one source line, if the file is available."""
    if root is None or line < 1:
        return None
    try:
        lines = (root / path).read_text(errors="replace").splitlines()
    except OSError:
        return None
    return " ".join(lines[line - 1].split()) if line <= len(lines) else None


def _short_rule(check_id: str) -> str:
    """Local Semgrep rules are reported with their file path prepended; keep the rule's own ID."""
    match = re.search(r"(sentineledge-[a-z0-9-]+)$", check_id)
    return match.group(1) if match else check_id


# --- SAST ---------------------------------------------------------------------------------------


def parse_semgrep(doc: dict[str, Any], root: Path | None = None) -> list[Finding]:
    findings = []
    for r in doc.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        rule = _short_rule(r["check_id"])
        path = relative_path(r["path"], root)
        line = int(r.get("start", {}).get("line", 0))
        declared = str(meta.get("sentineledge-severity", "")).lower()
        severity = (
            declared
            if declared in _SEVERITY_WORDS
            else _SEMGREP_LEVEL.get(extra.get("severity", ""), "medium")
        )
        code = _source_line(root, path, line)
        refs = meta.get("references") or []
        findings.append(
            Finding(
                tool="semgrep",
                category="sast",
                rule_id=rule,
                title=" ".join(str(extra.get("message", rule)).split())[:300],
                severity=severity,
                component=path,
                location=f"{path}:{line}",
                fingerprint=fingerprint("semgrep", rule, path, code if code is not None else line),
                recommendation=str(meta.get("cwe")) if meta.get("cwe") else None,
                references=tuple(str(x) for x in (refs if isinstance(refs, list) else [refs])),
            )
        )
    return findings


def parse_bandit(doc: dict[str, Any], root: Path | None = None) -> list[Finding]:
    findings = []
    for r in doc.get("results", []):
        path = relative_path(r["filename"], root)
        line = int(r.get("line_number", 0))
        # Bandit's "code" holds numbered context lines; keep the flagged one.
        code = None
        for raw in str(r.get("code", "")).splitlines():
            number, _, text = raw.partition(" ")
            if number == str(line):
                code = " ".join(text.split())
        findings.append(
            Finding(
                tool="bandit",
                category="sast",
                rule_id=r["test_id"],
                title=r.get("issue_text", r["test_id"]),
                severity=_BANDIT_LEVEL.get(r.get("issue_severity", ""), "medium"),
                component=path,
                location=f"{path}:{line}",
                fingerprint=fingerprint(
                    "bandit", r["test_id"], path, code if code is not None else line
                ),
                references=(r["more_info"],) if r.get("more_info") else (),
            )
        )
    return findings


# --- SCA and container images (Trivy) -----------------------------------------------------------


def _cvss_score(vuln: dict[str, Any]) -> float | None:
    scores = []
    for source in (vuln.get("CVSS") or {}).values():
        for key in ("V3Score", "V40Score", "V2Score"):
            if isinstance(source.get(key), (int, float)):
                scores.append(float(source[key]))
                break
    return max(scores) if scores else None


def parse_trivy(doc: dict[str, Any], root: Path | None = None) -> list[Finding]:
    """Trivy JSON (schema 2): `trivy fs` reports dependencies (sca), `trivy image` reports the
    image's OS packages and libraries (container)."""
    category = "container" if doc.get("ArtifactType") == "container_image" else "sca"
    artifact = str(doc.get("ArtifactName", ""))
    # Images are scanned from `docker save` tarballs, so ArtifactName is a file path; the tags
    # recorded in the image metadata name the image itself.
    tags = (doc.get("Metadata") or {}).get("RepoTags") or []
    image = str(tags[0]) if tags else artifact
    findings = []
    for result in doc.get("Results", []) or []:
        target = str(result.get("Target", ""))
        if category == "sca":
            target = relative_path(target, root)
        elif target.startswith(artifact):
            target = image + target[len(artifact) :]
        for v in result.get("Vulnerabilities", []) or []:
            pkg = v.get("PkgName", "?")
            installed = v.get("InstalledVersion", "?")
            component = f"{pkg}@{installed}"
            findings.append(
                Finding(
                    tool="trivy",
                    category=category,
                    rule_id=v["VulnerabilityID"],
                    title=v.get("Title") or v["VulnerabilityID"],
                    severity=_TRIVY_LEVEL.get(v.get("Severity", "UNKNOWN"), "medium"),
                    component=component,
                    location=target,
                    fingerprint=fingerprint(
                        "trivy",
                        v["VulnerabilityID"],
                        pkg,
                        installed,
                        image.split(":")[0] if category == "container" else target,
                    ),
                    cve=v["VulnerabilityID"],
                    cvss=_cvss_score(v),
                    fixed_version=v.get("FixedVersion") or None,
                    recommendation=f"Upgrade {pkg} to {v['FixedVersion']}"
                    if v.get("FixedVersion")
                    else "No fixed version published yet",
                    references=tuple(x for x in [v.get("PrimaryURL")] if x),
                )
            )
        for m in result.get("Misconfigurations", []) or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            line = (m.get("CauseMetadata") or {}).get("StartLine", 0)
            findings.append(
                Finding(
                    tool="trivy",
                    category="iac" if category == "sca" else "container",
                    rule_id=m.get("AVDID") or m.get("ID", "?"),
                    title=m.get("Title", "Misconfiguration"),
                    severity=_TRIVY_LEVEL.get(m.get("Severity", "UNKNOWN"), "medium"),
                    component=target,
                    location=f"{target}:{line}",
                    fingerprint=fingerprint("trivy", m.get("ID"), target, m.get("Message")),
                    recommendation=m.get("Resolution"),
                    references=tuple(x for x in [m.get("PrimaryURL")] if x),
                )
            )
        for s in result.get("Secrets", []) or []:
            findings.append(
                Finding(
                    tool="trivy",
                    category="secret",
                    rule_id=s.get("RuleID", "secret"),
                    title=s.get("Title", "Secret"),
                    severity="critical",
                    component=target,
                    location=f"{target}:{s.get('StartLine', 0)}",
                    fingerprint=fingerprint(
                        "trivy-secret", s.get("RuleID"), target, s.get("StartLine")
                    ),
                    recommendation="Revoke the secret, then remove it from the image",
                )
            )
    return findings


# --- IaC (Checkov) ------------------------------------------------------------------------------


def parse_checkov(doc: dict[str, Any] | list[Any], root: Path | None = None) -> list[Finding]:
    """Checkov writes one object per framework (a list when several ran). Without a Prisma Cloud
    key, checks carry no severity; a failed check is then treated as high, matching Checkov's
    own default of failing the run on any failed check."""
    reports = doc if isinstance(doc, list) else [doc]
    findings = []
    for report in reports:
        framework = report.get("check_type", "")
        for c in (report.get("results") or {}).get("failed_checks", []) or []:
            path = relative_path(c.get("repo_file_path") or c.get("file_path", "?"), root)
            lines = c.get("file_line_range") or [0, 0]
            severity = _CHECKOV_LEVEL.get(str(c.get("severity") or "").upper(), "high")
            findings.append(
                Finding(
                    tool="checkov",
                    category="secret" if framework == "secrets" else "iac",
                    rule_id=c["check_id"],
                    title=c.get("check_name", c["check_id"]),
                    severity="critical" if framework == "secrets" else severity,
                    component=path,
                    location=f"{path}:{lines[0]}",
                    fingerprint=fingerprint("checkov", c["check_id"], path, c.get("resource")),
                    recommendation=c.get("guideline"),
                    references=tuple(x for x in [c.get("guideline")] if x),
                )
            )
    return findings


# --- Secrets (Gitleaks) -------------------------------------------------------------------------


def parse_gitleaks(doc: list[dict[str, Any]], root: Path | None = None) -> list[Finding]:
    """Every leaked secret is critical: it must be revoked, not just deleted from the code."""
    findings = []
    for s in doc or []:
        path = relative_path(s.get("File", "?"), root)
        findings.append(
            Finding(
                tool="gitleaks",
                category="secret",
                rule_id=s.get("RuleID", "secret"),
                title=s.get("Description", "Secret in repository history"),
                severity="critical",
                component=path,
                location=f"{path}:{s.get('StartLine', 0)} ({str(s.get('Commit', ''))[:7]})",
                fingerprint=fingerprint(
                    "gitleaks", s.get("Fingerprint") or (s.get("RuleID"), path, s.get("Commit"))
                ),
                recommendation="Revoke and rotate the secret, then remove it from history",
            )
        )
    return findings


# --- DAST (OWASP ZAP) ---------------------------------------------------------------------------


def parse_zap(doc: dict[str, Any], root: Path | None = None) -> list[Finding]:
    """ZAP's traditional JSON report: one finding per alert type per site, located at its first
    affected URL, with the number of affected URLs in the title."""
    findings = []
    for site in doc.get("site", []) or []:
        host = site.get("@name", "?")
        for alert in site.get("alerts", []) or []:
            instances = alert.get("instances", []) or []
            first = instances[0].get("uri", host) if instances else host
            name = alert.get("alert") or alert.get("name", "ZAP alert")
            count = len(instances)
            cwe = alert.get("cweid")
            findings.append(
                Finding(
                    tool="zap",
                    category="dast",
                    rule_id=str(alert.get("pluginid", "?")),
                    title=f"{name} ({count} URL{'s' if count != 1 else ''})" if count else name,
                    severity=_ZAP_RISK.get(str(alert.get("riskcode", "1")), "low"),
                    component=host,
                    location=first,
                    fingerprint=fingerprint("zap", alert.get("pluginid"), host),
                    recommendation=_strip_html(alert.get("solution")),
                    references=(f"CWE-{cwe}",) if cwe and str(cwe) not in {"0", "-1"} else (),
                )
            )
    return findings


def _strip_html(text: object) -> str | None:
    if not text:
        return None
    return " ".join(re.sub(r"<[^>]+>", " ", str(text)).split())[:500]


# --- Reports directory --------------------------------------------------------------------------

Parser = Callable[[Any, Path | None], list[Finding]]

# File name patterns written by scripts/scan.sh. SBOMs and scanner logs are not findings.
_DISPATCH: tuple[tuple[str, Parser], ...] = (
    (r"^semgrep.*\.json$", parse_semgrep),
    (r"^bandit.*\.json$", parse_bandit),
    (r"^trivy.*\.json$", parse_trivy),
    (r"^checkov.*\.json$", parse_checkov),
    (r"^gitleaks.*\.json$", parse_gitleaks),
    (r"^zap.*\.json$", parse_zap),
)


def parser_for(name: str) -> Parser | None:
    for pattern, parser in _DISPATCH:
        if re.match(pattern, name):
            return parser
    return None


def load_reports(directory: Path, root: Path | None = None) -> tuple[list[Finding], list[str]]:
    """All findings from a reports directory, de-duplicated by fingerprint, and the report files
    read. A report that is not valid JSON is an error: a scan that failed silently must not pass
    the gate."""
    findings: dict[str, Finding] = {}
    read: list[str] = []
    for path in sorted(directory.iterdir()):
        parser = parser_for(path.name)
        if parser is None or not path.is_file():
            continue
        text = path.read_text().strip()
        doc: Any = json.loads(text) if text else ([] if path.name.startswith("gitleaks") else {})
        for finding in parser(doc, root):
            findings.setdefault(finding.fingerprint, finding)
        read.append(path.name)
    return list(findings.values()), read
