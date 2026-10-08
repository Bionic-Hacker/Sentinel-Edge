/**
 * Runtime shape checks for vulnerability management (Phase 8). Scanner output (titles, components,
 * locations, package names) is written by third parties: the UI renders it as text only.
 */
import {
  ACCEPTANCE_ENDS,
  FINDING_CATEGORIES,
  SCAN_SOURCES,
  SCAN_TOOLS,
  SEVERITIES,
  VULN_STATUSES,
  type AppRef,
  type LastScan,
  type RiskAcceptance,
  type SbomComponent,
  type SbomDetail,
  type SbomList,
  type SbomSummary,
  type ScanList,
  type ScanRef,
  type ScanSummary,
  type VulnerabilityDetail,
  type VulnerabilityOverview,
  type VulnerabilityPage,
  type VulnerabilitySummary,
} from "../types";
import { isRecord } from "./client";

const isString = (v: unknown): v is string => typeof v === "string";
const isNumber = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
const isBool = (v: unknown): v is boolean => typeof v === "boolean";
const nullable =
  <T>(check: (v: unknown) => v is T) =>
  (v: unknown): v is T | null =>
    v === null || check(v);
const oneOf =
  <T extends string>(values: readonly T[]) =>
  (v: unknown): v is T =>
    (values as readonly unknown[]).includes(v);
const arrayOf =
  <T>(check: (v: unknown) => v is T) =>
  (v: unknown): v is T[] =>
    Array.isArray(v) && v.every(check);
const isCounts = (v: unknown): v is Record<string, number> => isRecord(v) && Object.values(v).every(isNumber);

const isSeverity = oneOf(SEVERITIES);
const isStatus = oneOf(VULN_STATUSES);

export function isAppRef(v: unknown): v is AppRef {
  return isRecord(v) && isString(v.id) && isString(v.slug) && isString(v.name);
}

export function isScanRef(v: unknown): v is ScanRef {
  return isRecord(v) && isString(v.id) && isString(v.reference) && isString(v.imported_at);
}

export function isAcceptance(v: unknown): v is RiskAcceptance {
  return (
    isRecord(v) &&
    isString(v.id) &&
    isString(v.reference) &&
    isString(v.justification) &&
    isString(v.compensating_control) &&
    isString(v.approver_label) &&
    isString(v.created_at) &&
    isString(v.expires_at) &&
    nullable(isString)(v.ended_at) &&
    nullable(oneOf(ACCEPTANCE_ENDS))(v.end_reason) &&
    nullable(isString)(v.ended_by_label) &&
    isBool(v.in_force)
  );
}

export function isVulnerabilitySummary(v: unknown): v is VulnerabilitySummary {
  return (
    isRecord(v) &&
    isString(v.id) &&
    isString(v.reference) &&
    isAppRef(v.application) &&
    oneOf(SCAN_TOOLS)(v.tool) &&
    oneOf(FINDING_CATEGORIES)(v.category) &&
    isString(v.rule_id) &&
    isString(v.title) &&
    isSeverity(v.severity) &&
    isString(v.component) &&
    isString(v.location) &&
    nullable(isString)(v.cve) &&
    nullable(isString)(v.fixed_version) &&
    isBool(v.fixable) &&
    isStatus(v.status) &&
    isString(v.first_seen_at) &&
    isString(v.last_seen_at) &&
    nullable(isString)(v.resolved_at) &&
    nullable(isString)(v.sla_due_at) &&
    isBool(v.overdue) &&
    isNumber(v.times_reopened) &&
    isNumber(v.version)
  );
}

export function isVulnerabilityDetail(v: unknown): v is VulnerabilityDetail {
  return (
    isVulnerabilitySummary(v) &&
    isRecord(v) &&
    nullable(isNumber)(v.cvss) &&
    nullable(isString)(v.recommendation) &&
    arrayOf(isString)(v.references) &&
    nullable(isString)(v.status_note) &&
    isScanRef(v.first_scan) &&
    isScanRef(v.last_scan) &&
    arrayOf(isAcceptance)(v.acceptances) &&
    arrayOf(isStatus)(v.allowed_statuses) &&
    isBool(v.can_accept_risk) &&
    isBool(v.can_revoke_acceptance) &&
    isNumber(v.max_acceptance_days)
  );
}

export function isVulnerabilityPage(v: unknown): v is VulnerabilityPage {
  return isRecord(v) && arrayOf(isVulnerabilitySummary)(v.items) && nullable(isNumber)(v.next_before);
}

function isLastScan(v: unknown): v is LastScan {
  return (
    isRecord(v) &&
    isString(v.id) &&
    isString(v.reference) &&
    isAppRef(v.application) &&
    oneOf(SCAN_SOURCES)(v.source) &&
    isString(v.imported_at) &&
    isString(v.generated_at) &&
    nullable(isString)(v.commit_sha) &&
    isBool(v.gate_passed)
  );
}

export function isVulnerabilityOverview(v: unknown): v is VulnerabilityOverview {
  return (
    isRecord(v) &&
    isRecord(v.active) &&
    SEVERITIES.every((s) => isNumber((v.active as Record<string, unknown>)[s])) &&
    isNumber(v.active_total) &&
    isNumber(v.awaiting_fix) &&
    isNumber(v.overdue) &&
    isNumber(v.accepted) &&
    isNumber(v.false_positive) &&
    isNumber(v.fixed_30d) &&
    isCounts(v.by_category) &&
    nullable(isLastScan)(v.last_scan)
  );
}

export function isScanSummary(v: unknown): v is ScanSummary {
  return (
    isRecord(v) &&
    isString(v.id) &&
    isString(v.reference) &&
    isAppRef(v.application) &&
    oneOf(SCAN_SOURCES)(v.source) &&
    nullable(isString)(v.commit_sha) &&
    nullable(isString)(v.branch) &&
    isString(v.imported_by_label) &&
    isString(v.imported_at) &&
    isString(v.generated_at) &&
    arrayOf(isString)(v.reports) &&
    isBool(v.gate_passed) &&
    isRecord(v.summary)
  );
}

export function isScanList(v: unknown): v is ScanList {
  return isRecord(v) && arrayOf(isScanSummary)(v.items);
}

export function isSbomSummary(v: unknown): v is SbomSummary {
  return (
    isRecord(v) &&
    isString(v.id) &&
    isAppRef(v.application) &&
    isScanRef(v.scan) &&
    isString(v.artifact) &&
    isString(v.format) &&
    isString(v.spec_version) &&
    isString(v.subject) &&
    nullable(isString)(v.subject_version) &&
    isNumber(v.component_count) &&
    isString(v.document_sha256) &&
    isString(v.created_at)
  );
}

export function isSbomList(v: unknown): v is SbomList {
  return isRecord(v) && arrayOf(isSbomSummary)(v.items);
}

function isComponent(v: unknown): v is SbomComponent {
  return (
    isRecord(v) &&
    isString(v.name) &&
    nullable(isString)(v.version) &&
    nullable(isString)(v.type) &&
    nullable(isString)(v.purl) &&
    arrayOf(isString)(v.licenses)
  );
}

export function isSbomDetail(v: unknown): v is SbomDetail {
  return isSbomSummary(v) && isRecord(v) && arrayOf(isComponent)(v.components) && isNumber(v.components_total);
}
