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
