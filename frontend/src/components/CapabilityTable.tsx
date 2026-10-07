import type { Capability } from "../lib/types";
import { ProvenanceBadge } from "./ProvenanceBadge";

export function CapabilityTable({ items, caption }: { items: Capability[]; caption: string }) {
  if (items.length === 0) {
    return <p className="text-sm text-ink-muted">No capabilities are registered for this module yet.</p>;
  }
  return (
    <div className="overflow-x-auto rounded-md border border-line">
      <table className="w-full min-w-[640px] text-left text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead className="bg-raised text-ink-muted">
          <tr>
            <th scope="col" className="px-3 py-2 font-medium">Capability</th>
            <th scope="col" className="px-3 py-2 font-medium">Type</th>
            <th scope="col" className="px-3 py-2 font-medium">Status</th>
            <th scope="col" className="px-3 py-2 font-medium text-right">Phase</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {items.map((c) => (
            <tr key={c.key} className="align-top">
              <td className="px-3 py-2.5">
                <div className="font-medium text-ink">{c.name}</div>
                <div className="mt-0.5 max-w-prose text-ink-muted">{c.note}</div>
              </td>
              <td className="px-3 py-2.5"><ProvenanceBadge provenance={c.provenance} /></td>
              <td className="px-3 py-2.5">
                {c.status === "implemented" ? (
                  <span className="text-ok">Implemented</span>
                ) : (
                  <span className="text-ink-muted">Planned</span>
                )}
              </td>
              <td className="px-3 py-2.5 text-right tabular-nums text-ink-muted">{c.phase}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
