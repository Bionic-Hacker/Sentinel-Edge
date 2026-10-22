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
      "The edge runs in AWS only during a deploy window. What it blocks is in Audit Logs (WAF logs) and on the Threats page, its rules on the WAF page, its certificates on the Certificates page, and an edge check proves it from the internet (make edge-check).",
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
 * The sidebar's parent titles. Each groups related modules and opens or closes when pressed; the
 * group holding the current page opens by itself. Every module belongs to exactly one group.
 */
export interface NavGroup {
  id: string;
  label: string;
  paths: readonly string[];
}

export const NAV_GROUPS: readonly NavGroup[] = [
  { id: "overview", label: "Overview", paths: ["/", "/applications"] },
  { id: "edge", label: "Edge Security", paths: ["/edge", "/waf", "/threats", "/certificates"] },
  { id: "appsec", label: "Application Security", paths: ["/apis", "/vulnerabilities", "/sbom", "/ai-security"] },
  { id: "secops", label: "Security Operations", paths: ["/incidents", "/automation"] },
  { id: "grc", label: "Governance & Risk", paths: ["/threat-modeling", "/compliance", "/audit-logs"] },
  { id: "admin", label: "Administration", paths: ["/settings"] },
];

/** Inside a group the parent title already says "Edge Security", so its first page is the overview. */
export const NAV_LABEL: Readonly<Record<string, string>> = { "/edge": "Edge overview" };

/** The module a route belongs to (/incidents/12 is Incidents). */
export function moduleIndexFor(pathname: string): number {
  return MODULES.findIndex((m) =>
    m.path === "/" ? pathname === "/" : pathname === m.path || pathname.startsWith(`${m.path}/`),
  );
}

/** The group holding a route, if any. */
export function groupFor(pathname: string): NavGroup | undefined {
  const module = MODULES[moduleIndexFor(pathname)];
  return module ? NAV_GROUPS.find((g) => g.paths.includes(module.path)) : undefined;
}

/**
 * Each tab's backdrop (index.css, `.backdrop`): an industrial SOC console look drawn in CSS from
 * the theme accent. A pattern suited to the work, plus the tab's console code as a large outlined
 * mark, so every tab is distinct. Patterns only, no photos: nothing to license or download.
 */
export type Backdrop =
  | "radar"
  | "rack"
  | "circuit"
  | "hex"
  | "nodes"
  | "waveform"
  | "tread"
  | "blueprint";

const BACKDROPS: Readonly<Record<string, { pattern: Backdrop; code: string }>> =
  {
    "/": { pattern: "radar", code: "SOC-00" },
    "/applications": { pattern: "rack", code: "APP-01" },
    "/apis": { pattern: "circuit", code: "API-02" },
    "/waf": { pattern: "hex", code: "WAF-03" },
    "/edge": { pattern: "nodes", code: "EDG-04" },
    "/threats": { pattern: "radar", code: "THR-05" },
    "/incidents": { pattern: "waveform", code: "INC-06" },
    "/vulnerabilities": { pattern: "tread", code: "VLN-07" },
    "/threat-modeling": { pattern: "nodes", code: "TMD-08" },
    "/certificates": { pattern: "hex", code: "PKI-09" },
    "/ai-security": { pattern: "circuit", code: "AIS-10" },
    "/sbom": { pattern: "blueprint", code: "SBM-11" },
    "/compliance": { pattern: "blueprint", code: "CMP-12" },
    "/audit-logs": { pattern: "waveform", code: "AUD-13" },
    "/automation": { pattern: "rack", code: "AUT-14" },
    "/settings": { pattern: "tread", code: "SYS-15" },
  };

/** The backdrop for a route, matching the tab it belongs to (/incidents/12 is Incidents). */
export function backdropFor(
  pathname: string,
): { pattern: Backdrop; code: string; index: number } | undefined {
  const index = moduleIndexFor(pathname);
  const module = MODULES[index];
  const backdrop = module ? BACKDROPS[module.path] : undefined;
  return backdrop ? { ...backdrop, index } : undefined;
}
