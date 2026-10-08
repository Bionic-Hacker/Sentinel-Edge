/** Vulnerability management API (Phase 8): findings, risk acceptances, scans and SBOMs. */
import type { FindingCategory, ScanTool, Severity, VulnStatus } from "../types";
import { apiDownload, apiGet, apiRequest, type QueryValue } from "./client";
import {
  isSbomDetail,
  isSbomList,
  isScanList,
  isVulnerabilityDetail,
  isVulnerabilityOverview,
  isVulnerabilityPage,
} from "./vulnValidators";

const withSignal = (signal?: AbortSignal) => (signal ? { signal } : {});
const id = (value: string) => encodeURIComponent(value);

export interface VulnerabilityFilters {
  status?: readonly VulnStatus[];
  min_severity?: Severity | "";
  category?: FindingCategory | "";
  tool?: ScanTool | "";
  fixable?: "true" | "false" | "";
  overdue?: "true" | "";
  q?: string;
  before?: number;
  limit?: number;
}

export const listVulnerabilities = (filters: VulnerabilityFilters, signal?: AbortSignal) =>
  apiGet("/api/v1/vulnerabilities", isVulnerabilityPage, {
    query: { limit: 50, ...filters } as Record<string, QueryValue>,
    ...withSignal(signal),
  });

export const getVulnerabilityOverview = (signal?: AbortSignal) =>
  apiGet("/api/v1/vulnerabilities/overview", isVulnerabilityOverview, withSignal(signal));

export const getVulnerability = (vulnerabilityId: string, signal?: AbortSignal) =>
  apiGet(`/api/v1/vulnerabilities/${id(vulnerabilityId)}`, isVulnerabilityDetail, withSignal(signal));

export const changeVulnerabilityStatus = (
  vulnerabilityId: string,
  body: { status: VulnStatus; version: number; note?: string },
) =>
  apiRequest(`/api/v1/vulnerabilities/${id(vulnerabilityId)}/status`, isVulnerabilityDetail, {
    method: "POST",
    body,
  });

export const acceptRisk = (
  vulnerabilityId: string,
  body: { justification: string; compensating_control: string; expires_on: string; version: number },
) =>
  apiRequest(`/api/v1/vulnerabilities/${id(vulnerabilityId)}/acceptances`, isVulnerabilityDetail, {
    method: "POST",
    body,
  });

export const revokeAcceptance = (
  vulnerabilityId: string,
  acceptanceId: string,
  body: { note: string; version: number },
) =>
  apiRequest(
    `/api/v1/vulnerabilities/${id(vulnerabilityId)}/acceptances/${id(acceptanceId)}/revoke`,
    isVulnerabilityDetail,
    { method: "POST", body },
  );

export const listScans = (limit = 10, signal?: AbortSignal) =>
  apiGet("/api/v1/scans", isScanList, { query: { limit }, ...withSignal(signal) });

export const listSboms = (signal?: AbortSignal) => apiGet("/api/v1/sboms", isSbomList, withSignal(signal));

export const getSbom = (sbomId: string, query: { q?: string; limit?: number; offset?: number }, signal?: AbortSignal) =>
  apiGet(`/api/v1/sboms/${id(sbomId)}`, isSbomDetail, {
    query: query as Record<string, QueryValue>,
    ...withSignal(signal),
  });

export const downloadSbom = (sbomId: string) => apiDownload(`/api/v1/sboms/${id(sbomId)}/document`);
