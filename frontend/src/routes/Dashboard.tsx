import { useCapabilities } from "../app/capabilities-context";
import { CapabilityTable } from "../components/CapabilityTable";
import { PROVENANCE_ORDER, ProvenanceBadge, provenanceDescription } from "../components/ProvenanceBadge";
import { ErrorPanel } from "./ErrorPanel";

const CURRENT_PHASE = 1;
const PHASES = [
  "Architecture", "App foundation", "AWS foundation", "AWS deploy", "Edge, WAF, TLS", "API security",
  "Security ops", "AppSec scanning", "AI security", "Threat model & governance", "Automation", "Hardening",
];

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
        <h2 id="build-heading" className="mb-3 text-sm font-medium text-ink-muted">Build phases</h2>
        <ol className="grid grid-cols-2 gap-px overflow-hidden rounded-md border border-line bg-line sm:grid-cols-4 lg:grid-cols-6">
          {PHASES.map((name, i) => {
            const n = i + 1;
            const current = n === CURRENT_PHASE;
            return (
              <li
                key={name}
                aria-current={current ? "step" : undefined}
                className={`px-3 py-2.5 ${current ? "bg-raised" : "bg-surface"}`}
              >
                <span className={`block text-xs tabular-nums ${current ? "text-accent" : "text-ink-muted"}`}>
                  Phase {n}{current ? ", in progress" : ""}
                </span>
                <span className={`block text-sm ${current ? "text-ink" : "text-ink-muted"}`}>{name}</span>
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
