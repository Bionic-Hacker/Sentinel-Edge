/** Security operations API (Phase 7): dashboard, events, incidents, applications, simulator. */
import type {
  AppEnvironment,
  Criticality,
  DataView,
  EventCategory,
  EventSource,
  IncidentStatus,
  Resolution,
  Severity,
  WafMode,
} from "../types";
import { apiGet, apiRequest, type QueryValue } from "./client";
import {
  isApplication,
  isApplicationList,
  isEventDetail,
  isEventPage,
  isIncidentDetail,
  isIncidentPage,
  isOverview,
  isPeople,
  isRunList,
  isScenarioList,
  isSimulationRun,
  isWafMode,
  isWafRuleList,
} from "./secopsValidators";

const withSignal = (signal?: AbortSignal) => (signal ? { signal } : {});
const id = (value: string) => encodeURIComponent(value);

// --- Dashboard ----------------------------------------------------------------------------------

export const getOverview = (view: DataView, hours: number, signal?: AbortSignal) =>
  apiGet("/api/v1/security/overview", isOverview, { query: { view, hours }, ...withSignal(signal) });

// --- Events -------------------------------------------------------------------------------------

export interface EventFilters {
  view?: DataView | "all";
  category?: EventCategory | "";
  source?: EventSource | "";
  min_severity?: Severity | "";
  source_ip?: string;
  before_seq?: number;
  limit?: number;
}

export const listEvents = (filters: EventFilters, signal?: AbortSignal) =>
  apiGet("/api/v1/security-events", isEventPage, {
    query: { limit: 50, ...filters } as Record<string, QueryValue>,
    ...withSignal(signal),
  });

export const getEvent = (eventId: string, signal?: AbortSignal) =>
  apiGet(`/api/v1/security-events/${id(eventId)}`, isEventDetail, withSignal(signal));

// --- Incidents ----------------------------------------------------------------------------------

export interface IncidentFilters {
  view?: DataView | "all";
  state?: "open" | "closed" | "all" | IncidentStatus;
  owner?: "me" | "unassigned" | "";
  min_severity?: Severity | "";
  before_number?: number;
}

export const listIncidents = (filters: IncidentFilters, signal?: AbortSignal) =>
  apiGet("/api/v1/incidents", isIncidentPage, {
    query: { limit: 50, ...filters } as Record<string, QueryValue>,
    ...withSignal(signal),
  });

export const getIncident = (incidentId: string, signal?: AbortSignal) =>
  apiGet(`/api/v1/incidents/${id(incidentId)}`, isIncidentDetail, withSignal(signal));

export const createIncident = (body: {
  title: string;
  severity: Severity;
  summary?: string;
  category?: EventCategory;
  event_ids?: string[];
}) => apiRequest("/api/v1/incidents", isIncidentDetail, { method: "POST", body });

export const updateIncident = (
  incidentId: string,
  body: { version: number; title?: string; summary?: string; remediation?: string; severity?: Severity },
) => apiRequest(`/api/v1/incidents/${id(incidentId)}`, isIncidentDetail, { method: "PATCH", body });

export const transitionIncident = (
  incidentId: string,
  body: { version: number; to_status: IncidentStatus; resolution?: Resolution; note?: string },
) =>
  apiRequest(`/api/v1/incidents/${id(incidentId)}/transitions`, isIncidentDetail, { method: "POST", body });

export const assignIncident = (incidentId: string, body: { version: number; owner_id: string | null }) =>
  apiRequest(`/api/v1/incidents/${id(incidentId)}/assignment`, isIncidentDetail, { method: "POST", body });

export const addIncidentNote = (incidentId: string, body: string) =>
  apiRequest(`/api/v1/incidents/${id(incidentId)}/notes`, isIncidentDetail, {
    method: "POST",
    body: { body },
  });

export const linkIncidentEvents = (incidentId: string, body: { version: number; event_ids: string[] }) =>
  apiRequest(`/api/v1/incidents/${id(incidentId)}/events`, isIncidentDetail, { method: "POST", body });

export const listAssignees = async (signal?: AbortSignal) =>
  (await apiGet("/api/v1/incidents/assignees", isPeople, withSignal(signal))).items;

// --- Applications -------------------------------------------------------------------------------

export const listApplications = async (signal?: AbortSignal) =>
  (await apiGet("/api/v1/applications", isApplicationList, withSignal(signal))).items;

export const listApplicationOwners = async (signal?: AbortSignal) =>
  (await apiGet("/api/v1/applications/owners", isPeople, withSignal(signal))).items;

export const createApplication = (body: {
  slug: string;
  name: string;
  description?: string;
  owner_id?: string;
  environment: AppEnvironment;
  criticality: Criticality;
  domain?: string;
}) => apiRequest("/api/v1/applications", isApplication, { method: "POST", body });

export const updateApplication = (
  applicationId: string,
  body: {
    version: number;
    name?: string;
    description?: string;
    owner_id?: string;
    clear_owner?: boolean;
    environment?: AppEnvironment;
    criticality?: Criticality;
    domain?: string;
    status?: "active" | "retired";
  },
) => apiRequest(`/api/v1/applications/${id(applicationId)}`, isApplication, { method: "PATCH", body });

// --- Simulator ----------------------------------------------------------------------------------

export const listScenarios = async (signal?: AbortSignal) =>
  (await apiGet("/api/v1/simulator/scenarios", isScenarioList, withSignal(signal))).items;

export const listRuns = async (signal?: AbortSignal) =>
  (await apiGet("/api/v1/simulator/runs", isRunList, withSignal(signal))).items;

export const runScenario = (scenario: string) =>
  apiRequest("/api/v1/simulator/runs", isSimulationRun, { method: "POST", body: { scenario }, timeoutMs: 30000 });

export const listWafRules = (signal?: AbortSignal) =>
  apiGet("/api/v1/simulator/waf-rules", isWafRuleList, withSignal(signal));

export const setWafRuleMode = (ruleId: string, mode: WafMode) =>
  apiRequest(`/api/v1/simulator/waf-rules/${id(ruleId)}`, isWafMode, { method: "PUT", body: { mode } });
