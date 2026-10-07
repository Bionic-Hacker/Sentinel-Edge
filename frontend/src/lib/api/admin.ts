import type { AuditResult, ManagedUser, Role } from "../types";
import { apiGet, apiRequest } from "./client";
import { isAuditPage, isChainStatus, isManagedUser, isUserList } from "./validators";

export const listUsers = async (signal?: AbortSignal) =>
  (await apiGet("/api/v1/users", isUserList, signal ? { signal } : {})).items;

export const inviteUser = (body: { email: string; display_name: string; role: Role }) =>
  apiRequest("/api/v1/users", isManagedUser, { method: "POST", body });

export const updateUser = (
  id: string,
  body: Partial<Pick<ManagedUser, "display_name" | "role" | "is_active">>,
) => apiRequest(`/api/v1/users/${encodeURIComponent(id)}`, isManagedUser, { method: "PATCH", body });

export const resetUserMfa = (id: string) =>
  apiRequest(`/api/v1/users/${encodeURIComponent(id)}/mfa/reset`, isManagedUser, { method: "POST" });

export interface AuditFilters {
  action?: string;
  actor?: string;
  result?: AuditResult | "";
  before_seq?: number;
}

export const listAuditEntries = (filters: AuditFilters, signal?: AbortSignal) =>
  apiGet("/api/v1/audit-logs", isAuditPage, {
    query: { limit: 50, ...filters },
    ...(signal ? { signal } : {}),
  });

export const verifyAuditChain = () => apiGet("/api/v1/audit-logs/verify", isChainStatus);
