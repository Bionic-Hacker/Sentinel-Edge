import type { Provenance } from "../lib/types";

const STYLES: Record<Provenance, { label: string; className: string; description: string }> = {
  REAL_AWS: {
    label: "Real AWS",
    className: "text-prov-real border-prov-real/50 bg-prov-real/10",
    description: "Backed by a live, Terraform-managed AWS resource or API",
  },
  LOCAL: {
    label: "Local",
    className: "text-prov-local border-prov-local/50 bg-prov-local/10",
    description: "Real functionality running inside SentinelEdge",
  },
  SIMULATED: {
    label: "Simulated",
    className: "text-prov-sim border-prov-sim/50 bg-prov-sim/10",
    description: "Safe simulation; not a live security control",
  },
  DEMO: {
    label: "Demo data",
    className: "text-prov-demo border-prov-demo/50 bg-prov-demo/10",
    description: "Synthetic data for demonstration",
  },
};

export function ProvenanceBadge({ provenance }: { provenance: Provenance }) {
  const s = STYLES[provenance];
  return (
    <span
      className={`inline-flex items-center rounded-sm border px-1.5 py-0.5 text-xs font-medium ${s.className}`}
      title={s.description}
    >
      {s.label}
      <span className="sr-only">: {s.description}</span>
    </span>
  );
}

export const PROVENANCE_ORDER: readonly Provenance[] = ["REAL_AWS", "LOCAL", "SIMULATED", "DEMO"];
export const provenanceDescription = (p: Provenance) => STYLES[p].description;
