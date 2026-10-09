/**
 * Runtime shape checks for threat modeling and governance (Phase 10). Model and request text is
 * written by people: the UI renders it as text only.
 */
import {
  CATEGORY_STATES,
  CHANGE_STATUSES,
  CHANGE_TYPES,
  CONTROL_STATUSES,
  ELEMENT_KINDS,
  EXCEPTION_SCOPES,
  EXCEPTION_STATUSES,
  FACTOR_KINDS,
  MODEL_METHODS,
  MODEL_ORIGINS,
  MODEL_STATUSES,
  RISK_LEVELS,
  THREAT_STATUSES,
  WAF_MODES,
  type ChangeDetail,
  type ChangeList,
  type ChangeSummary,
  type Control,
  type ControlExtension,
  type ControlList,
  type Evidence,
  type ExceptionDetail,
  type ExceptionList,
  type ExceptionSummary,
  type HistoryEntry,
  type ModelElement,
  type Posture,
  type PostureCategory,
  type PostureFactor,
  type Requirement,
  type Threat,
  type ThreatModelDetail,
  type ThreatModelSummary,
} from "../types";
import { isRecord } from "./client";
import { isAppRef } from "./vulnValidators";

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
const isStrings = arrayOf(isString);
const isTextMap = (v: unknown): v is Record<string, string> => isRecord(v) && Object.values(v).every(isString);

const isEvidence = (v: unknown): v is Evidence => isRecord(v) && isString(v.kind) && isString(v.ref);

const isExtension = (v: unknown): v is ControlExtension =>
  isRecord(v) &&
  isNumber(v.phase) &&
  isString(v.title) &&
  isString(v.implementation) &&
  arrayOf(isEvidence)(v.evidence) &&
  isString(v.evidence_text);

export function isControl(v: unknown): v is Control {
  return (
    isRecord(v) &&
    isString(v.ref) &&
    isString(v.title) &&
    isString(v.family) &&
    nullable(isString)(v.layer) &&
    oneOf(CONTROL_STATUSES)(v.status) &&
    isNumber(v.phase) &&
    isString(v.implementation) &&
    arrayOf(isEvidence)(v.evidence) &&
    isString(v.evidence_text) &&
    arrayOf(isExtension)(v.extensions) &&
    isStrings(v.threats)
  );
}

export const isControlList = (v: unknown): v is ControlList =>
  isRecord(v) && arrayOf(isControl)(v.items) && isCounts(v.counts) && isString(v.catalogue_digest);

const isThreatRef = (v: unknown): v is Requirement["threats"][number] =>
  isRecord(v) && isString(v.ref) && isString(v.title) && oneOf(THREAT_STATUSES)(v.status) && isNumber(v.risk);

export const isRequirement = (v: unknown): v is Requirement =>
  isRecord(v) &&
  isString(v.ref) &&
  isString(v.title) &&
  arrayOf(isThreatRef)(v.threats) &&
  isStrings(v.controls) &&
  isString(v.control_text) &&
  isString(v.implementation) &&
  arrayOf(isEvidence)(v.evidence) &&
  isString(v.evidence_text) &&
  isString(v.phase_text);

export const isRequirementList = (v: unknown): v is { items: Requirement[] } =>
  isRecord(v) && arrayOf(isRequirement)(v.items);

export function isThreatModelSummary(v: unknown): v is ThreatModelSummary {
  return (
    isRecord(v) &&
    isString(v.id) &&
    isString(v.reference) &&
    isString(v.name) &&
    isAppRef(v.application) &&
    oneOf(MODEL_METHODS)(v.method) &&
    oneOf(MODEL_ORIGINS)(v.origin) &&
    oneOf(MODEL_STATUSES)(v.status) &&
    isString(v.version_label) &&
    isNumber(v.threat_count) &&
    isCounts(v.by_status) &&
    isNumber(v.highest_open_risk) &&
    isString(v.updated_at) &&
    isNumber(v.version)
  );
}

export const isThreatModelList = (v: unknown): v is { items: ThreatModelSummary[] } =>
  isRecord(v) && arrayOf(isThreatModelSummary)(v.items);

const isElement = (v: unknown): v is ModelElement =>
  isRecord(v) &&
  isString(v.id) &&
  oneOf(ELEMENT_KINDS)(v.kind) &&
  isString(v.ref) &&
  isString(v.name) &&
  isString(v.description) &&
  isStrings(v.boundaries) &&
  isStrings(v.threats) &&
  isBool(v.retired);

const isThreatControl = (v: unknown): v is Threat["controls"][number] =>
  isRecord(v) && isString(v.ref) && isString(v.title) && oneOf(CONTROL_STATUSES)(v.status) && isNumber(v.phase);

export const isThreat = (v: unknown): v is Threat =>
  isRecord(v) &&
  isString(v.id) &&
  isString(v.ref) &&
  isString(v.title) &&
  isString(v.stride) &&
  isString(v.owasp) &&
  isString(v.group) &&
  isStrings(v.boundaries) &&
  isNumber(v.likelihood) &&
  isNumber(v.impact) &&
  isNumber(v.risk) &&
  isString(v.mitigation) &&
  oneOf(THREAT_STATUSES)(v.status) &&
  isString(v.status_text) &&
  arrayOf(isNumber)(v.phases) &&
  arrayOf(isThreatControl)(v.controls) &&
  isBool(v.retired) &&
  isNumber(v.version);

const isCell = (v: unknown): v is ThreatModelDetail["stats"]["matrix"][number] => isRecord(v) && isNumber(v.likelihood) && isNumber(v.impact) && isNumber(v.count);

export function isThreatModelDetail(v: unknown): v is ThreatModelDetail {
  const stats = isRecord(v) ? v.stats : null;
  const perms = isRecord(v) ? v.permissions : null;
  return (
    isRecord(v) &&
    isString(v.id) &&
    isString(v.reference) &&
    isString(v.name) &&
    isAppRef(v.application) &&
    oneOf(MODEL_METHODS)(v.method) &&
    oneOf(MODEL_ORIGINS)(v.origin) &&
    oneOf(MODEL_STATUSES)(v.status) &&
    isString(v.scope) &&
    isString(v.version_label) &&
    isTextMap(v.pasta) &&
    arrayOf(isElement)(v.elements) &&
    arrayOf(isThreat)(v.threats) &&
    isRecord(stats) &&
    isCounts(stats.by_status) &&
    isCounts(stats.by_stride) &&
    arrayOf(isCell)(stats.matrix) &&
    isStrings(stats.unmapped) &&
    isStrings(stats.only_planned_controls) &&
    isRecord(perms) &&
    isBool(perms.can_edit) &&
    isBool(perms.maintained_as_code) &&
    isString(v.created_by_label) &&
    isString(v.created_at) &&
    isString(v.updated_at) &&
    isNumber(v.version)
  );
}

const isHistory = (v: unknown): v is HistoryEntry =>
  isRecord(v) &&
  isNumber(v.seq) &&
  isString(v.occurred_at) &&
  isString(v.action) &&
  isString(v.actor_label) &&
  nullable(isString)(v.note);

export const isExceptionSummary = (v: unknown): v is ExceptionSummary =>
  isRecord(v) &&
  isString(v.id) &&
  isString(v.reference) &&
  isString(v.title) &&
  isAppRef(v.application) &&
  oneOf(EXCEPTION_SCOPES)(v.scope) &&
  isString(v.scope_ref) &&
  oneOf(RISK_LEVELS)(v.risk_level) &&
  oneOf(EXCEPTION_STATUSES)(v.status) &&
  isString(v.requester_label) &&
  nullable(isString)(v.approver_label) &&
  isString(v.expires_on) &&
  nullable(isNumber)(v.days_left) &&
  isBool(v.imported) &&
  isNumber(v.version);

export function isExceptionDetail(v: unknown): v is ExceptionDetail {
  const perms = isRecord(v) ? v.permissions : null;
  return (
    isExceptionSummary(v) &&
    isRecord(v) &&
    nullable(isTextMap)(v.gate_match) &&
    isString(v.risk) &&
    isString(v.justification) &&
    isString(v.compensating_control) &&
    isStrings(v.control_refs) &&
    isString(v.implementation) &&
    isString(v.exit_criteria) &&
    nullable(isString)(v.decided_at) &&
    nullable(isString)(v.decision_note) &&
    nullable(isString)(v.ended_at) &&
    nullable(isString)(v.end_note) &&
    isNumber(v.max_days) &&
    isString(v.created_at) &&
    isRecord(perms) &&
    isBool(perms.can_decide) &&
    isBool(perms.can_close) &&
    isBool(perms.separation_of_duties) &&
    arrayOf(isHistory)(v.history)
  );
}

export const isExceptionList = (v: unknown): v is ExceptionList =>
  isRecord(v) && arrayOf(isExceptionSummary)(v.items) && isCounts(v.counts);

export const isChangeSummary = (v: unknown): v is ChangeSummary =>
  isRecord(v) &&
  isString(v.id) &&
  isString(v.reference) &&
  isString(v.title) &&
  isAppRef(v.application) &&
  oneOf(CHANGE_TYPES)(v.change_type) &&
  oneOf(RISK_LEVELS)(v.risk_level) &&
  oneOf(CHANGE_STATUSES)(v.status) &&
  isString(v.requester_label) &&
  nullable(isString)(v.approver_label) &&
  isString(v.created_at) &&
  isString(v.updated_at) &&
  isNumber(v.version);

const isWafTarget = (v: unknown): v is { rule_id: string; mode: (typeof WAF_MODES)[number] } =>
  isRecord(v) && isString(v.rule_id) && oneOf(WAF_MODES)(v.mode);
const isWafState = (v: unknown): v is { mode: (typeof WAF_MODES)[number] } =>
  isRecord(v) && oneOf(WAF_MODES)(v.mode);

export const isChangeDetail = (v: unknown): v is ChangeDetail =>
  isChangeSummary(v) &&
  isRecord(v) &&
  isString(v.description) &&
  isString(v.impact) &&
  isString(v.rollback_plan) &&
  isString(v.validation_plan) &&
  nullable(isWafTarget)(v.target) &&
  nullable(isWafState)(v.previous_state) &&
  nullable(isString)(v.decided_at) &&
  nullable(isString)(v.decision_note) &&
  nullable(isString)(v.implemented_at) &&
  nullable(isString)(v.implemented_by_label) &&
  nullable(isString)(v.implementation_ref) &&
  nullable(isString)(v.closed_at) &&
  nullable(isString)(v.closing_note) &&
  arrayOf(oneOf(CHANGE_STATUSES))(v.available_moves) &&
  isBool(v.separation_of_duties) &&
  arrayOf(isHistory)(v.history);

export const isChangeList = (v: unknown): v is ChangeList =>
  isRecord(v) && arrayOf(isChangeSummary)(v.items) && isCounts(v.counts);

const isFactor = (v: unknown): v is PostureFactor =>
  isRecord(v) &&
  oneOf(FACTOR_KINDS)(v.kind) &&
  isString(v.label) &&
  isNumber(v.points) &&
  isStrings(v.refs) &&
  nullable(isString)(v.link);

const isCategory = (v: unknown): v is PostureCategory =>
  isRecord(v) &&
  isString(v.key) &&
  isString(v.label) &&
  isNumber(v.score) &&
  oneOf(CATEGORY_STATES)(v.state) &&
  isNumber(v.implemented) &&
  isNumber(v.planned) &&
  arrayOf(isFactor)(v.factors);

const isTrendPoint = (v: unknown): v is Posture["trend"][number] =>
  isRecord(v) && isString(v.taken_at) && isNumber(v.overall) && isNumber(v.built_scope);

export const isPosture = (v: unknown): v is Posture =>
  isRecord(v) &&
  isNumber(v.overall) &&
  isNumber(v.built_scope) &&
  arrayOf(isCategory)(v.categories) &&
  isString(v.method) &&
  arrayOf(isTrendPoint)(v.trend) &&
  isString(v.computed_at);
