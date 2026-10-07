import { useCapabilities } from "../app/capabilities-context";
import { CapabilityTable } from "../components/CapabilityTable";
import { PROVENANCE_ORDER, ProvenanceBadge, provenanceDescription } from "../components/ProvenanceBadge";
import { ErrorPanel } from "./ErrorPanel";

const PHASE_NAMES: Record<number, string> = {
  1: "Architecture",
  2: "App foundation",
  3: "AWS foundation",
  4: "AWS deploy",
  5: "Edge, WAF, TLS",
  6: "API security",
  7: "Security ops",
  8: "AppSec scanning",
  9: "AI security",
  10: "Threat model & governance",
  11: "Automation",
  12: "Hardening",
};
// Local-first order (ADR-0016): everything that runs locally is built first; the AWS phases are
// grouped near the end so cloud resources exist for as short a time as possible.
const BUILD_ORDER = [1, 2, 6, 7, 8, 10, 9, 3, 4, 5, 11, 12];
const COMPLETE = new Set([1, 2, 6]);
const NEXT = BUILD_ORDER.find((n) => !COMPLETE.has(n));

export function Dashboard() {
  const caps = useCapabilities();

  return (
    <div className="max-w-6xl space-y-8">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Platform status</h1>
        <p className="mt-1 max-w-prose text-ink-muted">
          What SentinelEdge does today, and what is real, local, simulated, or demo data. Security
          telemetry panels arrive in phase 7; until then this page reports only facts the platform
          can verify.
        </p>
      </header>

      <section aria-labelledby="build-heading">
        <h2 id="build-heading" className="mb-1 text-sm font-medium text-ink-muted">Build phases</h2>
        <p className="mb-3 text-xs text-ink-muted">
          In build order: local work first, AWS phases grouped late to keep cloud costs down.
        </p>
        <ol className="grid grid-cols-2 gap-px overflow-hidden rounded-md border border-line bg-line sm:grid-cols-4 lg:grid-cols-6">
          {BUILD_ORDER.map((n) => {
            const done = COMPLETE.has(n);
            const next = n === NEXT;
            return (
              <li
                key={n}
                aria-current={next ? "step" : undefined}
                className={`px-3 py-2.5 ${next ? "bg-raised" : "bg-surface"}`}
              >
                <span
                  className={`block text-xs tabular-nums ${done ? "text-ok" : next ? "text-accent" : "text-ink-muted"}`}
                >
                  Phase {n}
                  {done ? ", complete" : next ? ", next" : ""}
                </span>
                <span className={`block text-sm ${done || next ? "text-ink" : "text-ink-muted"}`}>
                  {PHASE_NAMES[n]}
                </span>
              </li>
            );
          })}
        </ol>
      </section>

      <section aria-labelledby="register-heading" className="space-y-3">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <h2 id="register-heading" className="text-lg font-semibold">Capability register</h2>
          <dl className="flex flex-wrap gap-x-5 gap-y-2 text-sm">
            {PROVENANCE_ORDER.map((p) => {
              const count = caps.state === "ready" ? caps.data.filter((c) => c.provenance === p).length : null;
              return (
                <div key={p} className="flex items-center gap-2" title={provenanceDescription(p)}>
                  <dt><ProvenanceBadge provenance={p} /></dt>
                  <dd className="tabular-nums text-ink-muted">{count ?? "–"}</dd>
                </div>
              );
            })}
          </dl>
        </div>
        {caps.state === "loading" && <p className="text-sm text-ink-muted">Loading capabilities…</p>}
        {caps.state === "error" && <ErrorPanel error={caps.error} />}
        {caps.state === "ready" && (
          <CapabilityTable
            caption="All SentinelEdge capabilities with provenance, status, and delivery phase"
            items={[...caps.data].sort((a, b) => a.phase - b.phase || a.name.localeCompare(b.name))}
          />
        )}
      </section>
    </div>
  );
}
