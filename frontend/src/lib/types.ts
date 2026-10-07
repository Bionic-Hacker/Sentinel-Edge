/** Mirrors backend/app/core/provenance.py. The four classes are mandatory (spec §43). */
export const PROVENANCES = ["REAL_AWS", "LOCAL", "SIMULATED", "DEMO"] as const;
export type Provenance = (typeof PROVENANCES)[number];

export const STATUSES = ["implemented", "planned"] as const;
export type CapabilityStatus = (typeof STATUSES)[number];

export interface Capability {
  key: string;
  name: string;
  area: string;
  provenance: Provenance;
  status: CapabilityStatus;
  phase: number;
  note: string;
}

export interface Health {
  status: "ok";
  version: string;
}
