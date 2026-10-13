/** The edge in AWS read back (ADR-0029): environment, WAF block counts, ACM certificates. */
import { SEVERITIES, type Severity } from "../types";
import { apiGet, apiRequest, isRecord } from "./client";

export interface EnvironmentInfo {
  environment: string;
  deployed: boolean;
  region: string | null;
}

export interface SyncStatus {
  started_at: string | null;
  finished_at: string | null;
  waf_records_read: number;
  waf_events_stored: number;
  certificates_checked: number;
  certificate_events_stored: number;
  errors: string[];
}

export interface EdgeStatus {
  waf_logs_enabled: boolean;
  waf_log_group: string | null;
  certificate_regions: string[];
  sync_interval_seconds: number;
  last_sync: SyncStatus | null;
  waf_blocks_24h: number;
  waf_blocks_by_rule: { rule: string; count: number }[];
}

export interface Certificate {
  arn: string;
  region: string;
  domain: string;
  alternative_names: string[];
  status: string;
  type: string;
  key_algorithm: string | null;
  issuer: string | null;
  not_before: string | null;
  not_after: string | null;
  days_left: number | null;
  renewal_eligibility: string | null;
  renewal_status: string | null;
  in_use_by: number;
  condition: string | null;
  severity: Severity | null;
}

export interface CertificateList {
  enabled: boolean;
  regions: string[];
  items: Certificate[];
  error: string | null;
}

const str = (v: unknown): v is string => typeof v === "string";
const optStr = (v: unknown): v is string | null => v === null || typeof v === "string";
const num = (v: unknown): v is number => typeof v === "number";
const strList = (v: unknown): v is string[] => Array.isArray(v) && v.every(str);

export const isEnvironment = (v: unknown): v is EnvironmentInfo =>
  isRecord(v) && str(v.environment) && typeof v.deployed === "boolean" && optStr(v.region);

export const isSyncStatus = (v: unknown): v is SyncStatus =>
  isRecord(v) &&
  optStr(v.started_at) &&
  optStr(v.finished_at) &&
  num(v.waf_records_read) &&
  num(v.waf_events_stored) &&
  num(v.certificates_checked) &&
  num(v.certificate_events_stored) &&
  strList(v.errors);

export const isEdgeStatus = (v: unknown): v is EdgeStatus =>
  isRecord(v) &&
  typeof v.waf_logs_enabled === "boolean" &&
  optStr(v.waf_log_group) &&
  strList(v.certificate_regions) &&
  num(v.sync_interval_seconds) &&
  (v.last_sync === null || isSyncStatus(v.last_sync)) &&
  num(v.waf_blocks_24h) &&
  Array.isArray(v.waf_blocks_by_rule) &&
  v.waf_blocks_by_rule.every((r) => isRecord(r) && str(r.rule) && num(r.count));

export const isCertificate = (v: unknown): v is Certificate =>
  isRecord(v) &&
  str(v.arn) &&
  str(v.region) &&
  str(v.domain) &&
  strList(v.alternative_names) &&
  str(v.status) &&
  str(v.type) &&
  optStr(v.key_algorithm) &&
  optStr(v.issuer) &&
  optStr(v.not_before) &&
  optStr(v.not_after) &&
  (v.days_left === null || num(v.days_left)) &&
  optStr(v.renewal_eligibility) &&
  optStr(v.renewal_status) &&
  num(v.in_use_by) &&
  optStr(v.condition) &&
  (v.severity === null || (SEVERITIES as readonly unknown[]).includes(v.severity));

export const isCertificateList = (v: unknown): v is CertificateList =>
  isRecord(v) &&
  typeof v.enabled === "boolean" &&
  strList(v.regions) &&
  Array.isArray(v.items) &&
  v.items.every(isCertificate) &&
  optStr(v.error);

const opts = (signal?: AbortSignal) => (signal ? { signal } : {});

export const getEnvironment = (signal?: AbortSignal) =>
  apiGet("/api/v1/platform/environment", isEnvironment, opts(signal));

export const getEdgeStatus = (signal?: AbortSignal) => apiGet("/api/v1/edge/status", isEdgeStatus, opts(signal));

export const listCertificates = (signal?: AbortSignal) =>
  apiGet("/api/v1/edge/certificates", isCertificateList, opts(signal));

export const syncEdge = () => apiRequest("/api/v1/edge/sync", isSyncStatus, { method: "POST" });
