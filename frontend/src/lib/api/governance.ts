/** Threat modeling and governance API (Phase 10). */
import type {
  ChangeStatus,
  ChangeType,
  ControlStatus,
  ElementKind,
  ExceptionScope,
  ExceptionStatus,
  ModelMethod,
  ModelStatus,
  PastaStage,
  RiskLevel,
  ThreatStatus,
  WafMode,
} from "../types";
import { apiGet, apiRequest, type QueryValue } from "./client";
import {
  isChangeDetail,
  isChangeList,
  isControlList,
  isExceptionDetail,
  isExceptionList,
  isPosture,
  isRequirementList,
  isThreatModelDetail,
  isThreatModelList,
} from "./governanceValidators";

const withSignal = (signal?: AbortSignal) => (signal ? { signal } : {});
const id = (value: string) => encodeURIComponent(value);

export const listControls = (
  filters: { status?: ControlStatus | ""; family?: string; q?: string },
  signal?: AbortSignal,
) =>
  apiGet("/api/v1/governance/controls", isControlList, {
    query: filters as Record<string, QueryValue>,
    ...withSignal(signal),
  });

export const listRequirements = (signal?: AbortSignal) =>
  apiGet("/api/v1/governance/requirements", isRequirementList, withSignal(signal));

export const getPosture = (signal?: AbortSignal) => apiGet("/api/v1/governance/posture", isPosture, withSignal(signal));

export const takeSnapshot = () =>
  apiRequest("/api/v1/governance/posture/snapshots", isPosture, { method: "POST", body: {} });

export const listThreatModels = (signal?: AbortSignal) =>
  apiGet("/api/v1/threat-models", isThreatModelList, withSignal(signal));

export const getThreatModel = (modelId: string, signal?: AbortSignal) =>
  apiGet(`/api/v1/threat-models/${id(modelId)}`, isThreatModelDetail, withSignal(signal));

export const createThreatModel = (body: { application_id: string; name: string; method: ModelMethod; scope: string }) =>
  apiRequest("/api/v1/threat-models", isThreatModelDetail, { method: "POST", body });

export const updateThreatModel = (
  modelId: string,
  body: { version: number; name?: string; scope?: string; status?: ModelStatus; pasta?: Partial<Record<PastaStage, string>> },
) => apiRequest(`/api/v1/threat-models/${id(modelId)}`, isThreatModelDetail, { method: "PATCH", body });

export const archiveThreatModel = (modelId: string, version: number) =>
  apiRequest(`/api/v1/threat-models/${id(modelId)}/archive`, isThreatModelDetail, { method: "POST", body: { version } });

export const deleteThreatModel = (modelId: string) =>
  apiRequest(`/api/v1/threat-models/${id(modelId)}`, null, { method: "DELETE" });

export const addElement = (
  modelId: string,
  body: { kind: ElementKind; name: string; description: string; boundaries: string[] },
) => apiRequest(`/api/v1/threat-models/${id(modelId)}/elements`, isThreatModelDetail, { method: "POST", body });

export const updateElement = (modelId: string, elementId: string, body: { retired: boolean }) =>
  apiRequest(`/api/v1/threat-models/${id(modelId)}/elements/${id(elementId)}`, isThreatModelDetail, {
    method: "PATCH",
    body,
  });

export interface ThreatInput {
  title: string;
  stride: string;
  owasp: string;
  boundaries: string[];
  likelihood: number;
  impact: number;
  mitigation: string;
  status: ThreatStatus;
  controls: string[];
}

export const addThreat = (modelId: string, body: ThreatInput) =>
  apiRequest(`/api/v1/threat-models/${id(modelId)}/threats`, isThreatModelDetail, { method: "POST", body });

export const updateThreat = (modelId: string, threatId: string, body: Partial<ThreatInput> & { version: number; retired?: boolean }) =>
  apiRequest(`/api/v1/threat-models/${id(modelId)}/threats/${id(threatId)}`, isThreatModelDetail, {
    method: "PATCH",
    body,
  });

export const listExceptions = (signal?: AbortSignal) =>
  apiGet("/api/v1/exceptions", isExceptionList, withSignal(signal));

export const getException = (exceptionId: string, signal?: AbortSignal) =>
  apiGet(`/api/v1/exceptions/${id(exceptionId)}`, isExceptionDetail, withSignal(signal));

export interface ExceptionInput {
  title: string;
  scope: ExceptionScope;
  scope_ref: string;
  gate_match?: Record<string, string>;
  risk_level: RiskLevel;
  risk: string;
  justification: string;
  compensating_control: string;
  control_refs: string[];
  implementation: string;
  exit_criteria: string;
  expires_on: string;
}

export const requestException = (body: ExceptionInput) =>
  apiRequest("/api/v1/exceptions", isExceptionDetail, { method: "POST", body });

export const decideException = (exceptionId: string, body: { approve: boolean; note: string; version: number }) =>
  apiRequest(`/api/v1/exceptions/${id(exceptionId)}/decision`, isExceptionDetail, { method: "POST", body });

export const closeException = (exceptionId: string, body: { note: string; version: number }) =>
  apiRequest(`/api/v1/exceptions/${id(exceptionId)}/close`, isExceptionDetail, { method: "POST", body });

export const listChanges = (signal?: AbortSignal) =>
  apiGet("/api/v1/change-requests", isChangeList, withSignal(signal));

export const getChange = (changeId: string, signal?: AbortSignal) =>
  apiGet(`/api/v1/change-requests/${id(changeId)}`, isChangeDetail, withSignal(signal));

export interface ChangeInput {
  title: string;
  change_type: ChangeType;
  description: string;
  risk_level: RiskLevel;
  impact: string;
  rollback_plan: string;
  validation_plan: string;
  target?: { rule_id: string; mode: WafMode };
}

export const submitChange = (body: ChangeInput) =>
  apiRequest("/api/v1/change-requests", isChangeDetail, { method: "POST", body });

export const transitionChange = (
  changeId: string,
  body: { to: ChangeStatus; note: string; version: number; implementation_ref?: string },
) => apiRequest(`/api/v1/change-requests/${id(changeId)}/transition`, isChangeDetail, { method: "POST", body });

export type { ExceptionStatus };
