/**
 * Navigation and module definitions (spec §42 order). Each module names the capability keys
 * it will own, so its page shows exactly what is implemented, planned, real, or simulated —
 * pulled live from the API's capability register rather than written as static marketing.
 */
export interface ModuleDef {
  path: string;
  label: string;
  purpose: string;
  phase: number;
  capabilityKeys: readonly string[];
  /** Once the module's phase has shipped and it has no page of its own: where its data lives. */
  builtNote?: string;
}

export const MODULES: readonly ModuleDef[] = [
  {
    path: "/",
    label: "Dashboard",
    purpose:
      "Overall security posture, traffic, and active threats across protected applications.",
    phase: 7,
    capabilityKeys: [
      "platform.health",
      "platform.security_headers",
      "platform.error_handling",
      "platform.db_least_privilege",
      "secops.dashboard",
    ],
  },
  {
    path: "/applications",
    label: "Applications",
    purpose:
      "Inventory of protected applications with owners, criticality, and security score.",
    phase: 7,
    capabilityKeys: ["apps.inventory"],
  },
  {
    path: "/apis",
    label: "APIs",
    purpose:
      "Endpoint inventory with authentication, authorization, rate limits, and OWASP API Top 10 risk.",
    phase: 6,
    capabilityKeys: [
      "api.inventory",
      "api.rate_limit",
      "api.metrics",
      "api.ssrf_guard",
      "platform.trusted_hosts",
      "platform.client_ip",
    ],
  },
  {
    path: "/waf",
    label: "WAF",
    purpose:
      "AWS WAF rules, match counts, false positives, exceptions, and change requests.",
    phase: 5,
    capabilityKeys: ["aws.waf", "aws.waf_logs", "sim.waf_toggle"],
  },
  {
    path: "/edge",
    label: "Edge Security",
    purpose:
      "CloudFront distribution, origin protection, TLS policy, and security headers.",
    phase: 5,
    capabilityKeys: [
      "aws.edge",
      "aws.network",
      "platform.security_headers",
      "platform.client_ip",
    ],
    builtNote:
      "The edge runs in AWS only during a deploy window. What it blocks is on the WAF and Threats pages, its certificates on the Certificates page, and an edge check proves it from the internet (make edge-check).",
  },
  {
    path: "/threats",
    label: "Threats",
    purpose:
      "Detected attack activity by type: injection, XSS, SSRF, credential stuffing, bots, API abuse.",
    phase: 7,
    capabilityKeys: [
      "secops.events",
      "secops.http_analysis",
      "secops.correlation",
      "sim.attacks",
      "aws.waf_logs",
    ],
  },
  {
    path: "/incidents",
    label: "Incidents",
    purpose:
      "Incident lifecycle from detection to closure, with evidence, analysis, and remediation.",
    phase: 7,
    capabilityKeys: ["secops.incidents"],
  },
  {
    path: "/vulnerabilities",
    label: "Vulnerabilities",
    purpose:
      "Findings from code, dependency, container, and infrastructure scanning, tracked to closure.",
    phase: 8,
    capabilityKeys: ["vuln.management", "devsecops.scanning"],
  },
  {
    path: "/threat-modeling",
    label: "Threat Modeling",
    purpose:
      "STRIDE and PASTA models: assets, trust boundaries, data flows, threats, and residual risk.",
    phase: 10,
    capabilityKeys: ["governance.threat_model"],
  },
  {
    path: "/certificates",
    label: "Certificates",
    purpose:
      "Certificate inventory, expiry, validation, and renewal status with alerting.",
    phase: 5,
    capabilityKeys: ["aws.certificates"],
  },
  {
    path: "/ai-security",
    label: "AI Security",
    purpose:
      "AI-assisted analysis on Amazon Bedrock with prompt defenses and human approval.",
    phase: 9,
    capabilityKeys: ["ai.analysis", "ai.approval"],
  },
  {
    path: "/sbom",
    label: "SBOM",
    purpose:
      "Software bill of materials per build: components, versions, licenses, known vulnerabilities.",
    phase: 8,
    capabilityKeys: ["devsecops.sbom"],
  },
  {
    path: "/compliance",
    label: "Compliance",
    purpose:
      "Security control matrix, explainable posture score, exceptions, and risk acceptance.",
    phase: 10,
    capabilityKeys: ["governance.controls", "governance.exceptions"],
  },
  {
    path: "/audit-logs",
    label: "Audit Logs",
    purpose:
      "Tamper-evident record of logins, configuration changes, and administrative actions.",
    phase: 2,
    capabilityKeys: [
      "audit.log",
      "platform.structured_logging",
      "aws.foundation",
      "aws.observability",
    ],
  },
  {
    path: "/automation",
    label: "Automation",
    purpose:
      "Security automation, attack simulations against SentinelEdge only, and demo scenarios.",
    phase: 11,
    capabilityKeys: [
      "automation.tools",
      "sim.attacks",
      "demo.scenarios",
      "devsecops.precommit",
    ],
  },
  {
    path: "/settings",
    label: "Settings",
    purpose: "Users, roles, multi-factor authentication, and session policy.",
    phase: 2,
    capabilityKeys: ["identity.auth", "identity.rbac", "identity.user_admin"],
  },
];

/**
 * Each tab's background pattern, drawn in CSS from the theme's accent (index.css, `.backdrop`).
 * Grouped by the kind of work: operations watch, security filters traffic, governance records,
 * platform configures. Patterns only, no photos: nothing to license, nothing to download.
 */
export type Backdrop = "radar" | "circuit" | "blueprint" | "nodes";

const BACKDROPS: Readonly<Record<string, Backdrop>> = {
  "/": "radar",
  "/threats": "radar",
  "/incidents": "radar",
  "/vulnerabilities": "radar",
  "/applications": "circuit",
  "/apis": "circuit",
  "/waf": "circuit",
  "/edge": "circuit",
  "/threat-modeling": "blueprint",
  "/certificates": "blueprint",
  "/sbom": "blueprint",
  "/compliance": "blueprint",
  "/audit-logs": "blueprint",
  "/ai-security": "nodes",
  "/automation": "nodes",
  "/settings": "nodes",
};

/** The backdrop for a route, matching the tab it belongs to (/incidents/12 is Incidents). */
export function backdropFor(
  pathname: string,
): { pattern: Backdrop; index: number } | undefined {
  const index = MODULES.findIndex((m) =>
    m.path === "/"
      ? pathname === "/"
      : pathname === m.path || pathname.startsWith(`${m.path}/`),
  );
  const module = MODULES[index];
  const pattern = module ? BACKDROPS[module.path] : undefined;
  return pattern ? { pattern, index } : undefined;
}
