/** Mirrors backend/app/core/provenance.py. The four classes are mandatory (spec §43). */
export const PROVENANCES = ["REAL_AWS", "LOCAL", "SIMULATED", "DEMO"] as const;
export type Provenance = (typeof PROVENANCES)[number];

export const STATUSES = ["implemented", "planned"] as const;
export type CapabilityStatus = (typeof STATUSES)[number];

export interface Capability {
  key: string;
  name: string;
  area: string;
  provenance: Provenance;
  status: CapabilityStatus;
  phase: number;
  note: string;
}

export interface Health {
  status: "ok";
  version: string;
}

/** Mirrors backend/app/models/user.py. */
export const ROLES = ["ADMIN", "SECURITY_ENGINEER", "DEVELOPER", "ANALYST", "VIEWER"] as const;
export type Role = (typeof ROLES)[number];

export const PENDING_STEPS = ["mfa_enrollment", "password_change"] as const;
export type PendingStep = (typeof PENDING_STEPS)[number];

export interface UserProfile {
  id: string;
  email: string;
  display_name: string;
  role: Role;
  mfa_enabled: boolean;
  pending_steps: PendingStep[];
}

export interface AuthenticatedResponse {
  status: "authenticated";
  access_token: string;
  token_type: "bearer";
  expires_in: number;
  user: UserProfile;
}

export interface MfaRequiredResponse {
  status: "mfa_required";
  challenge_token: string;
  expires_in: number;
}

export interface ManagedUser {
  id: string;
  email: string;
  display_name: string;
  role: Role;
  is_active: boolean;
  mfa_enabled: boolean;
  must_change_password: boolean;
  locked: boolean;
  last_login_at: string | null;
  created_at: string;
}

export const AUDIT_RESULTS = ["success", "failure", "denied"] as const;
export type AuditResult = (typeof AUDIT_RESULTS)[number];

export interface AuditEntry {
  seq: number;
  id: string;
  occurred_at: string;
  actor_id: string | null;
  actor_label: string;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  result: AuditResult;
  source_ip: string | null;
  correlation_id: string | null;
  details: Record<string, unknown>;
  prev_hash: string;
  record_hash: string;
}

export interface AuditPage {
  items: AuditEntry[];
  next_before_seq: number | null;
}

export interface ChainStatus {
  intact: boolean;
  records_checked: number;
  head_hash: string;
  first_break_seq: number | null;
  problem: string | null;
}

// --- API Security Center (Phase 6) ------------------------------------------------------------
export const RISKS = ["critical", "high", "medium", "low"] as const;
export type Risk = (typeof RISKS)[number];
export const ENDPOINT_STATUSES = ["protected", "elevated", "review"] as const;
export type EndpointStatus = (typeof ENDPOINT_STATUSES)[number];
export const COVERAGE_STATUSES = ["mitigated", "partial", "not_exposed"] as const;
export type CoverageStatus = (typeof COVERAGE_STATUSES)[number];

export interface EndpointMetrics {
  requests: number;
  error_rate: number;
  client_errors: number;
  server_errors: number;
  unauthenticated: number;
  forbidden: number;
  throttled: number;
  security_rejections: number;
}

export interface InventoryItem {
  method: string;
  path: string;
  summary: string;
  authentication: string;
  authorization: string;
  roles: string[];
  object_rule: string | null;
  csrf_protected: boolean;
  risk: Risk;
  rate_limit: string;
  owasp: string[];
  data: string;
  metrics: EndpointMetrics;
  last_scan: string | null;
  scan_note: string;
  status: EndpointStatus;
  status_reasons: string[];
}

export interface InventorySummary {
  endpoints: number;
  public: number;
  critical: number;
  high: number;
  requests: number;
  security_rejections: number;
  throttled: number;
  unmatched_requests: number;
  needs_attention: number;
}

export interface Inventory {
  generated_at: string;
  window_hours: number;
  metrics_enabled: boolean;
  summary: InventorySummary;
  items: InventoryItem[];
}

export interface OwaspCategory {
  code: string;
  name: string;
  status: CoverageStatus;
  controls: string[];
  evidence: string[];
  planned: string | null;
  exposed_endpoints: number;
}

export interface OwaspCoverage {
  edition: string;
  items: OwaspCategory[];
}

// --- Security operations (Phase 7) --------------------------------------------------------------
/** Mirrors backend/app/models/security_event.py. */
export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];
export const EVENT_SOURCES = [
  "auth",
  "authz",
  "rate_limit",
  "http_analysis",
  "audit",
  "correlation",
  "waf",
  "certificate",
  "dependency",
  "appsec",
] as const;
export type EventSource = (typeof EVENT_SOURCES)[number];
export const EVENT_CATEGORIES = [
  "sql_injection",
  "xss",
  "path_traversal",
  "command_injection",
  "ssrf",
  "scanner",
  "recon",
  "bot",
  "auth_failure",
  "brute_force",
  "credential_stuffing",
  "token_theft",
  "bola",
  "bfla",
  "privilege_change",
  "rate_limit",
  "api_abuse",
  "audit_tampering",
  "suspicious_auth",
  "certificate",
  "vulnerable_dependency",
  "code_weakness",
  "exposed_secret",
] as const;
export type EventCategory = (typeof EVENT_CATEGORIES)[number];
export const OUTCOMES = ["allowed", "rejected", "throttled", "blocked", "detected"] as const;
export type Outcome = (typeof OUTCOMES)[number];

/** "live" = LOCAL and REAL_AWS; "simulated" = SIMULATED and DEMO. Never mixed. */
export type DataView = "live" | "simulated";

export interface SecurityEventSummary {
  id: string;
  seq: number;
  occurred_at: string;
  provenance: Provenance;
  source: EventSource;
  category: EventCategory;
  severity: Severity;
  outcome: Outcome;
  title: string;
  rule_id: string | null;
  source_ip: string | null;
  method: string | null;
  endpoint: string | null;
  status_code: number | null;
  actor_label: string | null;
  incident_id: string | null;
}

export interface SecurityEventDetail extends SecurityEventSummary {
  user_agent: string | null;
  correlation_id: string | null;
  /** Attacker-influenced data: render as text only. */
  evidence: Record<string, unknown>;
}

export interface EventPage {
  items: SecurityEventSummary[];
  next_before_seq: number | null;
}

/** Mirrors backend/app/models/incident.py. */
export const INCIDENT_STATUSES = [
  "DETECTED",
  "TRIAGED",
  "INVESTIGATING",
  "CONTAINMENT",
  "REMEDIATION",
  "VALIDATION",
  "CLOSED",
] as const;
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];
export const RESOLUTIONS = ["resolved", "accepted_risk", "false_positive", "duplicate"] as const;
export type Resolution = (typeof RESOLUTIONS)[number];
export const TIMELINE_KINDS = [
  "created",
  "status_changed",
  "note",
  "assigned",
  "updated",
  "severity_raised",
  "events_linked",
] as const;
export type TimelineKind = (typeof TIMELINE_KINDS)[number];

export interface Person {
  id: string;
  display_name: string;
  role: Role;
}

export interface IncidentSummary {
  id: string;
  reference: string;
  title: string;
  severity: Severity;
  category: EventCategory | null;
  status: IncidentStatus;
  resolution: Resolution | null;
  provenance: Provenance;
  source_ip: string | null;
  detection_rule: string | null;
  owner: Person | null;
  event_count: number;
  detected_at: string;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
}

export interface IncidentPage {
  items: IncidentSummary[];
  next_before_number: number | null;
}

export interface TimelineEntry {
  id: string;
  at: string;
  actor_label: string;
  kind: TimelineKind;
  from_status: IncidentStatus | null;
  to_status: IncidentStatus | null;
  body: string | null;
  details: Record<string, unknown>;
}

export interface AvailableMove {
  to_status: IncidentStatus;
  label: string;
  resolutions: Resolution[];
  note_required: boolean;
}

export interface IncidentPermissions {
  can_edit: boolean;
  can_change_severity: boolean;
  can_assign: boolean;
  can_take: boolean;
  can_add_note: boolean;
  can_link_events: boolean;
  moves: AvailableMove[];
}

export interface RiskScore {
  score: number;
  factors: { reason: string; points: number }[];
}

export interface Integrity {
  verified: boolean;
  entries_checked: number;
  first_mismatch: string | null;
}

export interface IncidentDetail extends IncidentSummary {
  summary: string;
  remediation: string | null;
  version: number;
  created_by_label: string;
  trigger_event: SecurityEventDetail | null;
  events: SecurityEventSummary[];
  timeline: TimelineEntry[];
  risk: RiskScore;
  integrity: Integrity;
  permissions: IncidentPermissions;
}

// --- Dashboard (spec §12) -----------------------------------------------------------------------
export interface Overview {
  view: DataView;
  window_hours: number;
  generated_at: string;
  status: { level: "ok" | "attention" | "critical"; reasons: string[] };
  incidents: {
    open: number;
    unassigned: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
    closed_in_window: number;
    mean_minutes_to_triage: number | null;
    mean_minutes_to_close: number | null;
  };
  recent_incidents: {
    id: string;
    reference: string;
    title: string;
    severity: Severity;
    status: IncidentStatus;
    detected_at: string;
  }[];
  events: {
    total: number;
    detections: number;
    stopped: number;
    reached_app: number;
    by_category: Record<string, number>;
    by_severity: Record<string, number>;
    by_outcome: Record<string, number>;
  };
  series: { hour: string; events: number; detections: number; high_or_critical: number }[];
  top_sources: {
    source_ip: string;
    events: number;
    max_severity: Severity;
    categories: EventCategory[];
    country: string | null;
    last_seen: string;
  }[];
  top_rules: { rule_id: string; events: number }[];
  countries: { country: string; events: number }[];
  traffic: {
    source: "api_metrics" | "simulator";
    requests: number;
    allowed: number;
    rejected: number;
    blocked_at_edge: number;
    errors: number;
    unknown_paths: number;
    by_method: Record<string, number>;
    series: { hour: string; requests: number; rejected: number; errors: number }[];
    top_endpoints: { method: string; endpoint: string; requests: number }[];
  };
  controls: Record<
    string,
    { status: "measured" | "simulated" | "planned" | "not_connected"; summary: string; values: Record<string, number> }
  >;
}

// --- Applications (spec §40) --------------------------------------------------------------------
export const APP_ENVIRONMENTS = ["local", "dev", "staging", "production"] as const;
export type AppEnvironment = (typeof APP_ENVIRONMENTS)[number];
export const CRITICALITIES = ["low", "medium", "high", "critical"] as const;
export type Criticality = (typeof CRITICALITIES)[number];

export interface Measure {
  status: "measured" | "not_connected" | "planned";
  value: number | null;
  note: string;
}

export interface Application {
  id: string;
  slug: string;
  name: string;
  description: string;
  owner: Person | null;
  environment: AppEnvironment;
  criticality: Criticality;
  domain: string | null;
  status: "active" | "retired";
  is_platform: boolean;
  version: number;
  created_at: string;
  updated_at: string;
  api_count: Measure;
  open_incidents: Measure;
  security_events_24h: Measure;
  waf_status: Measure;
  certificate_status: Measure;
  security_score: Measure;
  last_scan: Measure;
  vulnerability_count: Measure;
}

// --- Simulator (spec §23) -----------------------------------------------------------------------
export const WAF_MODES = ["block", "count", "off"] as const;
export type WafMode = (typeof WAF_MODES)[number];

export interface Scenario {
  scenario: string;
  name: string;
  description: string;
  demonstrates: string;
}

export interface SimulationRun {
  id: string;
  reference: string;
  scenario: string;
  started_by_label: string;
  started_at: string;
  completed_at: string;
  seed: number;
  summary: {
    requests?: Record<string, number>;
    events?: number;
    detections?: { rule_id: string; title: string; severity: Severity }[];
    incidents?: { id: string; reference: string; title: string; severity: Severity; opened: boolean }[];
    waf_modes?: Record<string, string>;
  };
}

export interface WafRule {
  rule_id: string;
  description: string;
  category: EventCategory;
  severity: Severity;
  comparable_group: string;
  mode: WafMode;
  matches_24h: number;
  updated_at: string | null;
  updated_by_label: string | null;
}

export interface WafRuleList {
  web_acl: string;
  note: string;
  items: WafRule[];
}

// --- Vulnerability management (Phase 8) ---------------------------------------------------------

export const VULN_STATUSES = ["open", "in_progress", "fixed", "accepted_risk", "false_positive"] as const;
export type VulnStatus = (typeof VULN_STATUSES)[number];
export const FINDING_CATEGORIES = ["sast", "sca", "secret", "container", "iac", "dast"] as const;
export type FindingCategory = (typeof FINDING_CATEGORIES)[number];
export const SCAN_TOOLS = ["semgrep", "bandit", "trivy", "gitleaks", "checkov", "zap"] as const;
export type ScanTool = (typeof SCAN_TOOLS)[number];
export const SCAN_SOURCES = ["local", "ci"] as const;
export type ScanSource = (typeof SCAN_SOURCES)[number];
export const ACCEPTANCE_ENDS = ["revoked", "expired", "fixed"] as const;
export type AcceptanceEnd = (typeof ACCEPTANCE_ENDS)[number];

export interface AppRef {
  id: string;
  slug: string;
  name: string;
}

export interface ScanRef {
  id: string;
  reference: string;
  imported_at: string;
}

export interface RiskAcceptance {
  id: string;
  reference: string;
  justification: string;
  compensating_control: string;
  approver_label: string;
  created_at: string;
  expires_at: string;
  ended_at: string | null;
  end_reason: AcceptanceEnd | null;
  ended_by_label: string | null;
  in_force: boolean;
}

export interface VulnerabilitySummary {
  id: string;
  reference: string;
  application: AppRef;
  tool: ScanTool;
  category: FindingCategory;
  rule_id: string;
  title: string;
  severity: Severity;
  component: string;
  location: string;
  cve: string | null;
  fixed_version: string | null;
  fixable: boolean;
  status: VulnStatus;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  sla_due_at: string | null;
  overdue: boolean;
  times_reopened: number;
  version: number;
}

export interface VulnerabilityDetail extends VulnerabilitySummary {
  cvss: number | null;
  recommendation: string | null;
  references: string[];
  status_note: string | null;
  first_scan: ScanRef;
  last_scan: ScanRef;
  acceptances: RiskAcceptance[];
  allowed_statuses: VulnStatus[];
  can_accept_risk: boolean;
  can_revoke_acceptance: boolean;
  max_acceptance_days: number;
}

export interface VulnerabilityPage {
  items: VulnerabilitySummary[];
  next_before: number | null;
}

export type SeverityCounts = Record<Severity, number>;

export interface LastScan {
  id: string;
  reference: string;
  application: AppRef;
  source: ScanSource;
  imported_at: string;
  generated_at: string;
  commit_sha: string | null;
  gate_passed: boolean;
}

export interface VulnerabilityOverview {
  active: SeverityCounts;
  active_total: number;
  awaiting_fix: number;
  overdue: number;
  accepted: number;
  false_positive: number;
  fixed_30d: number;
  by_category: Record<string, number>;
  last_scan: LastScan | null;
}

export interface ScanSummary {
  id: string;
  reference: string;
  application: AppRef;
  source: ScanSource;
  commit_sha: string | null;
  branch: string | null;
  imported_by_label: string;
  imported_at: string;
  generated_at: string;
  reports: string[];
  gate_passed: boolean;
  summary: Record<string, unknown>;
}

export interface ScanList {
  items: ScanSummary[];
}

export interface SbomSummary {
  id: string;
  application: AppRef;
  scan: ScanRef;
  artifact: string;
  format: string;
  spec_version: string;
  subject: string;
  subject_version: string | null;
  component_count: number;
  document_sha256: string;
  created_at: string;
}

export interface SbomList {
  items: SbomSummary[];
}

export interface SbomComponent {
  name: string;
  version: string | null;
  type: string | null;
  purl: string | null;
  licenses: string[];
}

export interface SbomDetail extends SbomSummary {
  components: SbomComponent[];
  components_total: number;
}
