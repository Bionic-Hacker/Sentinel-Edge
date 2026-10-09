/** AI security engine API (Phase 9): analyses, proposals and their human decisions. */
import type { AiProposalStatus, AiSubjectType } from "../types";
import { apiGet, apiRequest, type QueryValue } from "./client";
import {
  isAiAnalysisDetail,
  isAiAnalysisList,
  isAiProposal,
  isAiProposalList,
  isAiStatus,
} from "./aiValidators";

const withSignal = (signal?: AbortSignal) => (signal ? { signal } : {});
const id = (value: string) => encodeURIComponent(value);

export const getAiStatus = (signal?: AbortSignal) => apiGet("/api/v1/ai/status", isAiStatus, withSignal(signal));

// A real model can take tens of seconds (the server allows SENTINEL_AI_TIMEOUT_SECONDS, 30 by
// default, with one retry; nginx allows this endpoint 75 s): the client waits a little longer.
const ANALYSIS_TIMEOUT_MS = 80_000;

export const runAnalysis = (subject_type: AiSubjectType, subject_id: string) =>
  apiRequest("/api/v1/ai/analyses", isAiAnalysisDetail, {
    method: "POST",
    body: { subject_type, subject_id },
    timeoutMs: ANALYSIS_TIMEOUT_MS,
  });

export const listAnalyses = (filter: { subject_type?: AiSubjectType; subject_id?: string }, signal?: AbortSignal) =>
  apiGet("/api/v1/ai/analyses", isAiAnalysisList, { query: filter as Record<string, QueryValue>, ...withSignal(signal) });

export const getAnalysis = (analysisId: string, signal?: AbortSignal) =>
  apiGet(`/api/v1/ai/analyses/${id(analysisId)}`, isAiAnalysisDetail, withSignal(signal));

export const listProposals = (status: AiProposalStatus | undefined, signal?: AbortSignal) =>
  apiGet("/api/v1/ai/proposals", isAiProposalList, { query: { status }, ...withSignal(signal) });

export const decideProposal = (
  proposalId: string,
  body: { version: number; decision: "approve" | "reject"; note?: string },
) => apiRequest(`/api/v1/ai/proposals/${id(proposalId)}/decision`, isAiProposal, { method: "POST", body });
