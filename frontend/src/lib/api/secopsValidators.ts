/**
 * Runtime shape checks for the security operations API (Phase 7). As everywhere in the client,
 * the UI renders only what it has checked; evidence fields are attacker-influenced and are
 * rendered as text, never as markup.
 */
import {
  EVENT_CATEGORIES,
  EVENT_SOURCES,
  INCIDENT_STATUSES,
  OUTCOMES,
  PROVENANCES,
  RESOLUTIONS,
  ROLES,
  SEVERITIES,
  TIMELINE_KINDS,
  WAF_MODES,
  type Application,
  type EventPage,
  type IncidentDetail,
  type IncidentPage,
  type IncidentSummary,
  type Measure,
  type Overview,
  type Person,
  type Scenario,
  type SecurityEventDetail,
  type SecurityEventSummary,
  type SimulationRun,
  type TimelineEntry,
  type WafRule,
  type WafRuleList,
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
function arrayOf<T>(check: (v: unknown) => v is T): (v: unknown) => v is T[];
function arrayOf(check: (v: unknown) => boolean): (v: unknown) => v is unknown[];
function arrayOf(check: (v: unknown) => boolean) {
  return (v: unknown): v is unknown[] => Array.isArray(v) && v.every(check);
}
const isCounts = (v: unknown): v is Record<string, number> =>
  isRecord(v) && Object.values(v).every(isNumber);

const isSeverity = oneOf(SEVERITIES);
const isCategory = oneOf(EVENT_CATEGORIES);
const isStatus = oneOf(INCIDENT_STATUSES);

export function isEventSummary(v: unknown): v is SecurityEventSummary {
  return (
    isRecord(v) &&
    isString(v.id) &&
    isNumber(v.seq) &&
    isString(v.occurred_at) &&
    oneOf(PROVENANCES)(v.provenance) &&
    oneOf(EVENT_SOURCES)(v.source) &&
    isCategory(v.category) &&
    isSeverity(v.severity) &&
    oneOf(OUTCOMES)(v.outcome) &&
    isString(v.title) &&
    nullable(isString)(v.rule_id) &&
    nullable(isString)(v.source_ip) &&
    nullable(isString)(v.method) &&
    nullable(isString)(v.endpoint) &&
    nullable(isNumber)(v.status_code) &&
    nullable(isString)(v.actor_label) &&
    nullable(isString)(v.incident_id)
  );
}

export function isEventDetail(v: unknown): v is SecurityEventDetail {
  return (
    isEventSummary(v) &&
    isRecord(v) &&
    nullable(isString)(v.user_agent) &&
    nullable(isString)(v.correlation_id) &&
    isRecord(v.evidence)
  );
}

export const isEventPage = (v: unknown): v is EventPage =>
  isRecord(v) && arrayOf(isEventSummary)(v.items) && nullable(isNumber)(v.next_before_seq);

export const isPerson = (v: unknown): v is Person =>
  isRecord(v) && isString(v.id) && isString(v.display_name) && oneOf(ROLES)(v.role);

export const isPeople = (v: unknown): v is { items: Person[] } => isRecord(v) && arrayOf(isPerson)(v.items);

export function isIncidentSummary(v: unknown): v is IncidentSummary {
  return (
    isRecord(v) &&
    isString(v.id) &&
    isString(v.reference) &&
    isString(v.title) &&
    isSeverity(v.severity) &&
    nullable(isCategory)(v.category) &&
    isStatus(v.status) &&
    nullable(oneOf(RESOLUTIONS))(v.resolution) &&
    oneOf(PROVENANCES)(v.provenance) &&
    nullable(isString)(v.source_ip) &&
    nullable(isString)(v.detection_rule) &&
    nullable(isPerson)(v.owner) &&
    isNumber(v.event_count) &&
    isString(v.detected_at) &&
    isString(v.created_at) &&
    isString(v.updated_at) &&
    nullable(isString)(v.closed_at)
  );
}

export const isIncidentPage = (v: unknown): v is IncidentPage =>
  isRecord(v) && arrayOf(isIncidentSummary)(v.items) && nullable(isNumber)(v.next_before_number);

const isTimelineEntry = (v: unknown): v is TimelineEntry =>
  isRecord(v) &&
  isString(v.id) &&
  isString(v.at) &&
  isString(v.actor_label) &&
  oneOf(TIMELINE_KINDS)(v.kind) &&
  nullable(isStatus)(v.from_status) &&
  nullable(isStatus)(v.to_status) &&
  nullable(isString)(v.body) &&
  isRecord(v.details);

const isMove = (v: unknown) =>
  isRecord(v) &&
  isStatus(v.to_status) &&
  isString(v.label) &&
  arrayOf(oneOf(RESOLUTIONS))(v.resolutions) &&
  isBool(v.note_required);

export function isIncidentDetail(v: unknown): v is IncidentDetail {
  if (!isIncidentSummary(v) || !isRecord(v)) return false;
  const p = v.permissions;
  const risk = v.risk;
  const integrity = v.integrity;
  return (
    isString(v.summary) &&
    nullable(isString)(v.remediation) &&
    isNumber(v.version) &&
    isString(v.created_by_label) &&
    nullable(isEventDetail)(v.trigger_event) &&
    arrayOf(isEventSummary)(v.events) &&
    arrayOf(isTimelineEntry)(v.timeline) &&
    isRecord(risk) &&
    isNumber(risk.score) &&
    Array.isArray(risk.factors) &&
    risk.factors.every((f) => isRecord(f) && isString(f.reason) && isNumber(f.points)) &&
    isRecord(integrity) &&
    isBool(integrity.verified) &&
    isNumber(integrity.entries_checked) &&
    nullable(isString)(integrity.first_mismatch) &&
    isRecord(p) &&
    ["can_edit", "can_change_severity", "can_assign", "can_take", "can_add_note", "can_link_events"].every((k) =>
      isBool(p[k]),
    ) &&
    Array.isArray(p.moves) &&
    p.moves.every(isMove)
  );
}

const isHourPoint = (v: unknown) =>
  isRecord(v) && isString(v.hour) && isNumber(v.events) && isNumber(v.detections) && isNumber(v.high_or_critical);

export function isOverview(v: unknown): v is Overview {
  if (!isRecord(v)) return false;
  const { status, incidents, events, traffic, controls } = v;
  return (
    (v.view === "live" || v.view === "simulated") &&
    isNumber(v.window_hours) &&
    isString(v.generated_at) &&
    isRecord(status) &&
    oneOf(["ok", "attention", "critical"] as const)(status.level) &&
    arrayOf(isString)(status.reasons) &&
    isRecord(incidents) &&
    isNumber(incidents.open) &&
    isNumber(incidents.unassigned) &&
    isCounts(incidents.by_severity) &&
    isCounts(incidents.by_status) &&
    isNumber(incidents.closed_in_window) &&
    nullable(isNumber)(incidents.mean_minutes_to_triage) &&
    nullable(isNumber)(incidents.mean_minutes_to_close) &&
    arrayOf(
      (r: unknown) =>
        isRecord(r) &&
        isString(r.id) &&
        isString(r.reference) &&
        isString(r.title) &&
        isSeverity(r.severity) &&
        isStatus(r.status) &&
        isString(r.detected_at),
    )(v.recent_incidents) &&
    isRecord(events) &&
    ["total", "detections", "stopped", "reached_app"].every((k) => isNumber(events[k])) &&
    isCounts(events.by_category) &&
    isCounts(events.by_severity) &&
    isCounts(events.by_outcome) &&
    arrayOf(isHourPoint)(v.series) &&
    arrayOf(
      (s: unknown) =>
        isRecord(s) &&
        isString(s.source_ip) &&
        isNumber(s.events) &&
        isSeverity(s.max_severity) &&
        arrayOf(isCategory)(s.categories) &&
        nullable(isString)(s.country) &&
        isString(s.last_seen),
    )(v.top_sources) &&
    arrayOf((r: unknown) => isRecord(r) && isString(r.rule_id) && isNumber(r.events))(v.top_rules) &&
    arrayOf((c: unknown) => isRecord(c) && isString(c.country) && isNumber(c.events))(v.countries) &&
    isRecord(traffic) &&
    (traffic.source === "api_metrics" || traffic.source === "simulator") &&
    ["requests", "allowed", "rejected", "blocked_at_edge", "errors", "unknown_paths"].every((k) =>
      isNumber(traffic[k]),
    ) &&
    isCounts(traffic.by_method) &&
    arrayOf(
      (p: unknown) =>
        isRecord(p) && isString(p.hour) && isNumber(p.requests) && isNumber(p.rejected) && isNumber(p.errors),
    )(traffic.series) &&
    arrayOf(
      (e: unknown) => isRecord(e) && isString(e.method) && isString(e.endpoint) && isNumber(e.requests),
    )(traffic.top_endpoints) &&
    isRecord(controls) &&
    Object.values(controls).every(
      (c) =>
        isRecord(c) &&
        oneOf(["measured", "simulated", "planned"] as const)(c.status) &&
        isString(c.summary) &&
        isCounts(c.values),
    )
  );
}

const isMeasure = (v: unknown): v is Measure =>
  isRecord(v) &&
  oneOf(["measured", "not_connected", "planned"] as const)(v.status) &&
  nullable(isNumber)(v.value) &&
  isString(v.note);

export function isApplication(v: unknown): v is Application {
  return (
    isRecord(v) &&
    isString(v.id) &&
    isString(v.slug) &&
    isString(v.name) &&
    isString(v.description) &&
    nullable(isPerson)(v.owner) &&
    oneOf(["local", "dev", "staging", "production"] as const)(v.environment) &&
    oneOf(["low", "medium", "high", "critical"] as const)(v.criticality) &&
    nullable(isString)(v.domain) &&
    (v.status === "active" || v.status === "retired") &&
    isBool(v.is_platform) &&
    isNumber(v.version) &&
    isString(v.created_at) &&
    isString(v.updated_at) &&
    [
      "api_count",
      "open_incidents",
      "security_events_24h",
      "waf_status",
      "certificate_status",
      "security_score",
      "last_scan",
      "vulnerability_count",
    ].every((k) => isMeasure(v[k]))
  );
}

export const isApplicationList = (v: unknown): v is { items: Application[] } =>
  isRecord(v) && arrayOf(isApplication)(v.items);

const isScenario = (v: unknown): v is Scenario =>
  isRecord(v) && isString(v.scenario) && isString(v.name) && isString(v.description) && isString(v.demonstrates);

export const isScenarioList = (v: unknown): v is { items: Scenario[] } =>
  isRecord(v) && arrayOf(isScenario)(v.items);

export function isSimulationRun(v: unknown): v is SimulationRun {
  if (!isRecord(v) || !isRecord(v.summary)) return false;
  const s = v.summary;
  return (
    isString(v.id) &&
    isString(v.reference) &&
    isString(v.scenario) &&
    isString(v.started_by_label) &&
    isString(v.started_at) &&
    isString(v.completed_at) &&
    isNumber(v.seed) &&
    (s.requests === undefined || isCounts(s.requests)) &&
    (s.events === undefined || isNumber(s.events)) &&
    (s.detections === undefined ||
      arrayOf(
        (d: unknown) => isRecord(d) && isString(d.rule_id) && isString(d.title) && isSeverity(d.severity),
      )(s.detections)) &&
    (s.incidents === undefined ||
      arrayOf(
        (i: unknown) =>
          isRecord(i) &&
          isString(i.id) &&
          isString(i.reference) &&
          isString(i.title) &&
          isSeverity(i.severity) &&
          isBool(i.opened),
      )(s.incidents))
  );
}

export const isRunList = (v: unknown): v is { items: SimulationRun[] } =>
  isRecord(v) && arrayOf(isSimulationRun)(v.items);

const isWafRule = (v: unknown): v is WafRule =>
  isRecord(v) &&
  isString(v.rule_id) &&
  isString(v.description) &&
  isCategory(v.category) &&
  isSeverity(v.severity) &&
  isString(v.comparable_group) &&
  oneOf(WAF_MODES)(v.mode) &&
  isNumber(v.matches_24h) &&
  nullable(isString)(v.updated_at) &&
  nullable(isString)(v.updated_by_label);

export const isWafRuleList = (v: unknown): v is WafRuleList =>
  isRecord(v) && isString(v.web_acl) && isString(v.note) && arrayOf(isWafRule)(v.items);

export const isWafMode = (v: unknown): v is { mode: (typeof WAF_MODES)[number] } =>
  isRecord(v) && oneOf(WAF_MODES)(v.mode);
