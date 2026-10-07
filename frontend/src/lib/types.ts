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
