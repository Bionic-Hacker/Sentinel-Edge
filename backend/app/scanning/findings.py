"""The normalised finding: what every scanner's output is reduced to."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

# Most to least severe. The gate blocks on the first two.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
BLOCKING_SEVERITIES = frozenset({"critical", "high"})

# What kind of scan found it (spec §19).
CATEGORIES: tuple[str, ...] = ("sast", "sca", "secret", "container", "iac", "dast")


def severity_rank(severity: str) -> int:
    """0 for critical … 4 for info; unknown severities sort with medium."""
    return SEVERITIES.index(severity) if severity in SEVERITIES else 2


def fingerprint(*parts: object) -> str:
    """A stable identity for a finding, so the same issue is recognised across scans.

    Built from what identifies the issue (tool, rule, component, code), never from line numbers
    alone, which change whenever unrelated code moves."""
    joined = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(joined.encode()).hexdigest()[:32]


@dataclass(frozen=True)
class Finding:
    tool: str  # semgrep, bandit, trivy, checkov, gitleaks, zap
    category: str  # one of CATEGORIES
    rule_id: str  # scanner rule, CVE or check ID
    title: str
    severity: str  # one of SEVERITIES
    component: str  # file path, package@version, image or site
    location: str  # file:line, URL, or the component again
    fingerprint: str
    cve: str | None = None
    cvss: float | None = None
    fixed_version: str | None = None  # for package vulnerabilities: the first fixed version
    recommendation: str | None = None
    references: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_package_vulnerability(self) -> bool:
        return self.category in {"sca", "container"} and self.cve is not None

    @property
    def fixable(self) -> bool:
        """A fix exists. Code, configuration, secret and DAST findings are always fixable by
        changing this repository; a package vulnerability is fixable once an upstream release
        contains the fix."""
        return not self.is_package_vulnerability or bool(self.fixed_version)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["references"] = list(self.references)
        return data
