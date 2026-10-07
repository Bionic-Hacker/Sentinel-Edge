import { PROVENANCES, STATUSES, type Capability, type Health } from "../types";
import { apiGet, isRecord } from "./client";

export function isHealth(value: unknown): value is Health {
  return isRecord(value) && value.status === "ok" && typeof value.version === "string";
}

export function isCapability(value: unknown): value is Capability {
  return (
    isRecord(value) &&
    typeof value.key === "string" &&
    typeof value.name === "string" &&
    typeof value.area === "string" &&
    typeof value.note === "string" &&
    typeof value.phase === "number" &&
    (PROVENANCES as readonly unknown[]).includes(value.provenance) &&
    (STATUSES as readonly unknown[]).includes(value.status)
  );
}

export function isCapabilityList(value: unknown): value is { items: Capability[] } {
  return isRecord(value) && Array.isArray(value.items) && value.items.every(isCapability);
}

export const getHealth = (signal?: AbortSignal) =>
  apiGet("/api/v1/health", isHealth, signal ? { signal } : {});

export const getCapabilities = async (signal?: AbortSignal) =>
  (await apiGet("/api/v1/platform/capabilities", isCapabilityList, signal ? { signal } : {}))
    .items;
