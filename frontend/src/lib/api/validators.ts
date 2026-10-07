/** Runtime shape checks for API responses. The UI trusts nothing it hasn't checked. */
import {
  AUDIT_RESULTS,
  PENDING_STEPS,
  ROLES,
  type AuditEntry,
  type AuditPage,
  type AuthenticatedResponse,
  type ChainStatus,
  type ManagedUser,
  type MfaRequiredResponse,
  type UserProfile,
} from "../types";
import { isRecord } from "./client";

const isString = (v: unknown): v is string => typeof v === "string";
const isNullableString = (v: unknown): v is string | null => v === null || typeof v === "string";
const oneOf = <T extends string>(values: readonly T[]) => (v: unknown): v is T =>
  (values as readonly unknown[]).includes(v);
export const isRole = oneOf(ROLES);

export function isUserProfile(v: unknown): v is UserProfile {
  return (
    isRecord(v) &&
    isString(v.id) &&
    isString(v.email) &&
    isString(v.display_name) &&
    isRole(v.role) &&
    typeof v.mfa_enabled === "boolean" &&
    Array.isArray(v.pending_steps) &&
    v.pending_steps.every(oneOf(PENDING_STEPS))
  );
}

export function isAuthenticated(v: unknown): v is AuthenticatedResponse {
  return (
    isRecord(v) &&
    v.status === "authenticated" &&
    isString(v.access_token) &&
    v.token_type === "bearer" &&
    typeof v.expires_in === "number" &&
    isUserProfile(v.user)
  );
}

export function isMfaRequired(v: unknown): v is MfaRequiredResponse {
  return (
    isRecord(v) &&
    v.status === "mfa_required" &&
    isString(v.challenge_token) &&
    typeof v.expires_in === "number"
  );
}

export const isLoginResponse = (v: unknown): v is AuthenticatedResponse | MfaRequiredResponse =>
  isAuthenticated(v) || isMfaRequired(v);

export function isManagedUser(v: unknown): v is ManagedUser {
  return (
    isRecord(v) &&
    isString(v.id) &&
    isString(v.email) &&
    isString(v.display_name) &&
    isRole(v.role) &&
    typeof v.is_active === "boolean" &&
    typeof v.mfa_enabled === "boolean" &&
    typeof v.must_change_password === "boolean" &&
    typeof v.locked === "boolean" &&
    isNullableString(v.last_login_at) &&
    isString(v.created_at)
  );
}

export const isUserList = (v: unknown): v is { items: ManagedUser[] } =>
  isRecord(v) && Array.isArray(v.items) && v.items.every(isManagedUser);

export function isAuditEntry(v: unknown): v is AuditEntry {
  return (
    isRecord(v) &&
    typeof v.seq === "number" &&
    isString(v.id) &&
    isString(v.occurred_at) &&
    isNullableString(v.actor_id) &&
    isString(v.actor_label) &&
    isString(v.action) &&
    isNullableString(v.resource_type) &&
    isNullableString(v.resource_id) &&
    oneOf(AUDIT_RESULTS)(v.result) &&
    isNullableString(v.source_ip) &&
    isNullableString(v.correlation_id) &&
    isRecord(v.details) &&
    isString(v.prev_hash) &&
    isString(v.record_hash)
  );
}

export const isAuditPage = (v: unknown): v is AuditPage =>
  isRecord(v) &&
  Array.isArray(v.items) &&
  v.items.every(isAuditEntry) &&
  (v.next_before_seq === null || typeof v.next_before_seq === "number");

export const isChainStatus = (v: unknown): v is ChainStatus =>
  isRecord(v) &&
  typeof v.intact === "boolean" &&
  typeof v.records_checked === "number" &&
  isString(v.head_hash) &&
  (v.first_break_seq === null || typeof v.first_break_seq === "number") &&
  isNullableString(v.problem);

export const isEnrollmentStart = (v: unknown): v is { secret: string; otpauth_uri: string } =>
  isRecord(v) && isString(v.secret) && isString(v.otpauth_uri) && v.otpauth_uri.startsWith("otpauth://");

export const isRecoveryCodes = (v: unknown): v is { recovery_codes: string[] } =>
  isRecord(v) && Array.isArray(v.recovery_codes) && v.recovery_codes.every(isString);
