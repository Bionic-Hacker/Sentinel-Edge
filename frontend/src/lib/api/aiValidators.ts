/**
 * Runtime shape checks for the AI security engine (Phase 9). The AI's text and its quotes of
 * attacker-controlled data are rendered as text only; these checks make sure an answer has the
 * shape the page expects before any of it is shown.
 */
import {
  AI_ANALYSIS_STATUSES,
  AI_CLASSIFICATIONS,
  AI_PROPOSAL_STATUSES,
  AI_PROPOSAL_TYPES,
  AI_RISK_LEVELS,
  AI_SUBJECT_TYPES,
  PROVENANCES,
  SEVERITIES,
  type AiAction,
  type AiAnalysisDetail,
  type AiAnalysisList,
  type AiAnalysisSummary,
  type AiEvidence,
  type AiOutput,
  type AiProposal,
  type AiProposalList,
  type AiRecommendation,
  type AiStatus,
  type AiSubjectRef,
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
const isStrings = arrayOf(isString);

/** The fields each action type carries (its payload), checked by type. */
export function isActionFields(v: Record<string, unknown>): boolean {
  switch (v.type) {
    case "open_incident":
      return isString(v.title) && oneOf(SEVERITIES)(v.severity);
    case "raise_change_request":
      return isString(v.rule_id) && v.mode === "block";
    case "add_threat":
      return (
        isString(v.title) && isString(v.stride) && isNumber(v.likelihood) && isNumber(v.impact) && isStrings(v.controls)
      );
    default:
      return false;
  }
}

const isAction = (v: unknown): v is AiAction =>
  isRecord(v) && oneOf(AI_PROPOSAL_TYPES)(v.type) && isString(v.rationale) && isActionFields(v);

const isEvidence = (v: unknown): v is AiEvidence => isRecord(v) && isString(v.field) && isString(v.quote);

const isRecommendation = (v: unknown): v is AiRecommendation =>
  isRecord(v) && isString(v.text) && isStrings(v.controls);

export function isAiOutput(v: unknown): v is AiOutput {
  return (
    isRecord(v) &&
    isString(v.summary) &&
    oneOf(AI_CLASSIFICATIONS)(v.classification) &&
    oneOf(SEVERITIES)(v.severity) &&
    isNumber(v.confidence) &&
    arrayOf(isEvidence)(v.observed_evidence) &&
    isString(v.inference) &&
    arrayOf(isRecommendation)(v.recommendations) &&
    arrayOf(isAction)(v.proposed_actions)
  );
}

export function isAiStatus(v: unknown): v is AiStatus {
  return (
    isRecord(v) &&
    isBool(v.enabled) &&
    isString(v.provider) &&
    nullable(isString)(v.model) &&
    nullable(oneOf(PROVENANCES))(v.provenance) &&
    isBool(v.can_analyse) &&
    isNumber(v.requests_today) &&
    isNumber(v.requests_per_day) &&
    isNumber(v.tokens_today) &&
    isNumber(v.tokens_per_day) &&
    isNumber(v.max_output_tokens)
  );
}

const isSubject = (v: unknown): v is AiSubjectRef =>
  isRecord(v) && oneOf(AI_SUBJECT_TYPES)(v.type) && isString(v.id) && isString(v.reference);

export function isAiProposal(v: unknown): v is AiProposal {
  return (
    isRecord(v) &&
    isString(v.id) &&
    isString(v.reference) &&
    isString(v.analysis_id) &&
    isString(v.analysis_reference) &&
    isSubject(v.subject) &&
    oneOf(AI_PROPOSAL_TYPES)(v.action_type) &&
    isRecord(v.payload) &&
    v.payload.type === v.action_type &&
    isActionFields(v.payload) &&
    isString(v.rationale) &&
    oneOf(AI_PROPOSAL_STATUSES)(v.status) &&
    isNumber(v.input_risk) &&
    isBool(v.note_required) &&
    isBool(v.can_decide) &&
    nullable(isString)(v.decided_by_label) &&
    nullable(isString)(v.decided_at) &&
    nullable(isString)(v.decision_note) &&
    nullable(isString)(v.result_ref) &&
    isString(v.created_at) &&
    isNumber(v.version)
  );
}

export function isAiAnalysisSummary(v: unknown): v is AiAnalysisSummary {
  return (
    isRecord(v) &&
    isString(v.id) &&
    isString(v.reference) &&
    isSubject(v.subject) &&
    nullable(isAppRef)(v.application) &&
    oneOf(PROVENANCES)(v.provenance) &&
    oneOf(AI_ANALYSIS_STATUSES)(v.status) &&
    isString(v.provider) &&
    isString(v.model) &&
    isNumber(v.prompt_risk) &&
    oneOf(AI_RISK_LEVELS)(v.risk_level) &&
    nullable(oneOf(AI_CLASSIFICATIONS))(v.classification) &&
    nullable(oneOf(SEVERITIES))(v.severity) &&
    isNumber(v.proposals) &&
    isString(v.requested_by_label) &&
    isString(v.created_at)
  );
}

export function isAiAnalysisDetail(v: unknown): v is AiAnalysisDetail {
  return (
    isAiAnalysisSummary(v) &&
    isRecord(v) &&
    nullable(isString)(v.failure) &&
    isStrings(v.risk_signals) &&
    isString(v.input_sha256) &&
    isNumber(v.input_chars) &&
    isNumber(v.input_tokens) &&
    isNumber(v.output_tokens) &&
    isNumber(v.duration_ms) &&
    nullable(isAiOutput)(v.output) &&
    isStrings(v.disagreements) &&
    arrayOf(isAiProposal)(v.proposal_items)
  );
}

export const isAiAnalysisList = (v: unknown): v is AiAnalysisList =>
  isRecord(v) && arrayOf(isAiAnalysisSummary)(v.items);

export const isAiProposalList = (v: unknown): v is AiProposalList =>
  isRecord(v) &&
  arrayOf(isAiProposal)(v.items) &&
  isRecord(v.counts) &&
  AI_PROPOSAL_STATUSES.every((s) => isRecord(v.counts) && isNumber(v.counts[s]));
