import { apiGet } from "./client";
import { isInventory, isOwaspCoverage } from "./validators";

export const getInventory = (signal?: AbortSignal) =>
  apiGet("/api/v1/api-security/inventory", isInventory, signal ? { signal } : {});

export const getOwaspCoverage = (signal?: AbortSignal) =>
  apiGet("/api/v1/api-security/owasp", isOwaspCoverage, signal ? { signal } : {});
