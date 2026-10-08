import { useEffect, useMemo, useState } from "react";
import { useCapabilities } from "../../app/capabilities-context";
import { useCurrentUser } from "../../app/auth-context";
import { MODULES } from "../../app/modules";
import { CapabilityTable } from "../../components/CapabilityTable";
import { Button, FormError } from "../../components/forms";
import { getInventory, getOwaspCoverage } from "../../lib/api/apiSecurity";
import type { ApiError } from "../../lib/api/client";
import type {
  CoverageStatus,
  EndpointStatus,
  Inventory,
  InventoryItem,
  OwaspCategory,
  OwaspCoverage,
  Risk,
  Role,
} from "../../lib/types";
import { RISKS } from "../../lib/types";
import { ErrorPanel } from "../../routes/ErrorPanel";
import { asApiError } from "../auth/LoginPage";

const READERS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER", "DEVELOPER"];
const MODULE = MODULES.find((m) => m.path === "/apis");

const RISK_STYLE: Record<Risk, string> = {
  critical: "border-fail/60 bg-fail/10 text-fail",
  high: "border-prov-sim/60 bg-prov-sim/10 text-prov-sim",
  medium: "border-prov-local/50 bg-prov-local/10 text-prov-local",
  low: "border-line text-ink-muted",
};
const STATUS_STYLE: Record<EndpointStatus, { label: string; className: string }> = {
  protected: { label: "Protected", className: "text-ok" },
  elevated: { label: "Elevated", className: "text-prov-sim" },
  review: { label: "Review", className: "text-fail" },
};
const COVERAGE_STYLE: Record<CoverageStatus, { label: string; className: string }> = {
  mitigated: { label: "Mitigated", className: "border-ok/50 bg-ok/10 text-ok" },
  partial: { label: "Partial", className: "border-prov-sim/60 bg-prov-sim/10 text-prov-sim" },
  not_exposed: { label: "Not exposed", className: "border-line text-ink-muted" },
};

export function ApiSecurityPage() {
  const user = useCurrentUser();
  const allowed = READERS.includes(user.role);
  return (
    <div className="max-w-7xl space-y-8">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">API Security Center</h1>
        <p className="mt-1 max-w-prose text-ink-muted">
          Every API endpoint with its authentication, authorization, risk and rate limit, generated from the live
          route table, plus the last 24 hours of traffic and the OWASP API Security Top 10 coverage.
        </p>
      </header>
      {allowed ? (
        <ApiSecurityCenter />
      ) : (
        <p className="max-w-prose text-ink-muted">
          The API inventory maps the platform's attack surface, so it is available to administrators, security
          engineers and developers.
        </p>
      )}
      <ModuleCapabilities />
    </div>
  );
}

function ApiSecurityCenter() {
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [owasp, setOwasp] = useState<OwaspCoverage | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [version, setVersion] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    Promise.all([getInventory(controller.signal), getOwaspCoverage(controller.signal)])
      .then(([inv, cov]) => {
        setInventory(inv);
        setOwasp(cov);
        setError(null);
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(asApiError(err));
      });
    return () => controller.abort();
  }, [version]);

  if (error) return <FormError error={error} />;
  if (!inventory || !owasp) return <p className="text-sm text-ink-muted">Loading the API inventory…</p>;

  return (
    <>
      <Summary inventory={inventory} onRefresh={() => setVersion((v) => v + 1)} />
      <InventoryTable items={inventory.items} />
      <OwaspSection coverage={owasp} />
    </>
  );
}

function Summary({ inventory, onRefresh }: { inventory: Inventory; onRefresh: () => void }) {
  const s = inventory.summary;
  const tiles: { label: string; value: number; note: string; tone?: string | undefined }[] = [
    { label: "Endpoints", value: s.endpoints, note: `${s.public} public` },
    { label: "Critical or high risk", value: s.critical + s.high, note: `${s.critical} critical` },
    { label: "Requests", value: s.requests, note: `last ${inventory.window_hours} h` },
    {
      label: "Security rejections",
      value: s.security_rejections,
      note: "401, 403 and 429 responses",
      tone: s.security_rejections ? "text-prov-sim" : undefined,
    },
    { label: "Throttled", value: s.throttled, note: "rate limit reached", tone: s.throttled ? "text-prov-sim" : undefined },
    {
      label: "Unknown-path requests",
      value: s.unmatched_requests,
      note: "probing for undocumented endpoints",
      tone: s.unmatched_requests ? "text-prov-sim" : undefined,
    },
    {
      label: "Need attention",
      value: s.needs_attention,
      note: "elevated or review status",
      tone: s.needs_attention ? "text-fail" : "text-ok",
    },
  ];
  return (
    <section aria-labelledby="summary-heading" className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <h2 id="summary-heading" className="text-lg font-semibold">
          Overview
        </h2>
        <div className="flex items-center gap-3 text-xs text-ink-muted">
          <span>Generated {inventory.generated_at.replace("T", " ").slice(0, 19)} UTC</span>
          <Button variant="secondary" onClick={onRefresh}>
            Refresh
          </Button>
        </div>
      </div>
      {!inventory.metrics_enabled && (
        <p role="status" className="text-sm text-prov-sim">
          Request metrics are switched off in this environment, so traffic figures read zero.
        </p>
      )}
      <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-md border border-line bg-line sm:grid-cols-4 lg:grid-cols-7">
        {tiles.map((t) => (
          <div key={t.label} className="bg-surface px-3 py-3">
            <dt className="text-xs text-ink-muted">{t.label}</dt>
            <dd className={`mt-1 text-2xl font-semibold tabular-nums ${t.tone ?? "text-ink"}`}>{t.value}</dd>
            <dd className="text-xs text-ink-muted">{t.note}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function InventoryTable({ items }: { items: InventoryItem[] }) {
  const [risk, setRisk] = useState<Risk | "">("");
  const [status, setStatus] = useState<EndpointStatus | "">("");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState<string | null>(null);

  const visible = useMemo(
    () =>
      items.filter(
        (i) =>
          (!risk || i.risk === risk) &&
          (!status || i.status === status) &&
          (!query || `${i.method} ${i.path} ${i.summary}`.toLowerCase().includes(query.toLowerCase())),
      ),
    [items, risk, status, query],
  );

  return (
    <section aria-labelledby="inventory-heading" className="space-y-3">
      <h2 id="inventory-heading" className="text-lg font-semibold">
        Endpoint inventory
      </h2>
      <div className="flex flex-wrap items-end gap-3 text-sm" role="group" aria-label="Filter endpoints">
        <label className="space-y-1">
          <span className="block font-medium">Search</span>
          <input
            type="search"
            value={query}
            maxLength={100}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="/api/v1/users"
            className="rounded border border-line bg-canvas px-2 py-2"
          />
        </label>
        <label className="space-y-1">
          <span className="block font-medium">Risk</span>
          <select
            value={risk}
            onChange={(e) => setRisk(e.target.value as Risk | "")}
            className="rounded border border-line bg-canvas px-2 py-2"
          >
            <option value="">Any risk</option>
            {RISKS.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </label>
        <label className="space-y-1">
          <span className="block font-medium">Status</span>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value as EndpointStatus | "")}
            className="rounded border border-line bg-canvas px-2 py-2"
          >
            <option value="">Any status</option>
            {Object.entries(STATUS_STYLE).map(([value, s]) => (
              <option key={value} value={value}>
                {s.label}
              </option>
            ))}
          </select>
        </label>
        <p className="pb-2 text-ink-muted" aria-live="polite">
          {visible.length} of {items.length} endpoints
        </p>
      </div>

      <div className="overflow-x-auto rounded-md border border-line">
        <table className="w-full min-w-[1040px] text-left text-sm">
          <caption className="sr-only">API endpoints with their security controls and 24-hour metrics</caption>
          <thead className="bg-raised text-ink-muted">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">Endpoint</th>
              <th scope="col" className="px-3 py-2 font-medium">Authentication</th>
              <th scope="col" className="px-3 py-2 font-medium">Authorization</th>
              <th scope="col" className="px-3 py-2 font-medium">Risk</th>
              <th scope="col" className="px-3 py-2 font-medium">Rate limit</th>
              <th scope="col" className="px-3 py-2 text-right font-medium">Requests</th>
              <th scope="col" className="px-3 py-2 text-right font-medium">Error rate</th>
              <th scope="col" className="px-3 py-2 text-right font-medium">
                <abbr title="Security rejections: 401, 403 and 429 responses" className="no-underline">
                  Attacks
                </abbr>
              </th>
              <th scope="col" className="px-3 py-2 font-medium">Last scan</th>
              <th scope="col" className="px-3 py-2 font-medium">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {visible.map((item) => {
              const key = `${item.method} ${item.path}`;
              return (
                <InventoryRow
                  key={key}
                  item={item}
                  open={open === key}
                  onToggle={() => setOpen(open === key ? null : key)}
                />
              );
            })}
          </tbody>
        </table>
        {visible.length === 0 && <p className="px-3 py-4 text-sm text-ink-muted">No endpoints match these filters.</p>}
      </div>
    </section>
  );
}

function InventoryRow({ item, open, onToggle }: { item: InventoryItem; open: boolean; onToggle: () => void }) {
  const m = item.metrics;
  const status = STATUS_STYLE[item.status];
  return (
    <>
      <tr className="align-top">
        <td className="px-3 py-2.5">
          <div className="font-mono text-xs">
            <span className="mr-2 font-semibold text-accent">{item.method}</span>
            {item.path}
          </div>
          <div className="mt-0.5 text-xs text-ink-muted">{item.summary}</div>
          <button
            type="button"
            className="mt-1 text-xs text-accent underline-offset-2 hover:underline"
            aria-expanded={open}
            aria-label={`${open ? "Hide" : "Show"} details for ${item.method} ${item.path}`}
            onClick={onToggle}
          >
            {open ? "Hide details" : "Details"}
          </button>
        </td>
        <td className="px-3 py-2.5 text-xs">{item.authentication}</td>
        <td className="px-3 py-2.5 text-xs">
          {item.authorization}
          {item.object_rule && <span className="mt-0.5 block text-ink-muted">+ object-level rule</span>}
        </td>
        <td className="px-3 py-2.5">
          <span className={`inline-flex rounded-sm border px-1.5 py-0.5 text-xs font-medium capitalize ${RISK_STYLE[item.risk]}`}>
            {item.risk}
          </span>
        </td>
        <td className="whitespace-nowrap px-3 py-2.5 text-xs">{item.rate_limit}</td>
        <td className="px-3 py-2.5 text-right tabular-nums">{m.requests}</td>
        <td className="px-3 py-2.5 text-right tabular-nums">{(m.error_rate * 100).toFixed(1)}%</td>
        <td className={`px-3 py-2.5 text-right tabular-nums ${m.security_rejections ? "text-prov-sim" : ""}`}>
          {m.security_rejections}
        </td>
        <td className="whitespace-nowrap px-3 py-2.5 text-xs text-ink-muted">{item.last_scan ?? "Not scanned"}</td>
        <td className={`px-3 py-2.5 text-xs font-medium ${status.className}`}>{status.label}</td>
      </tr>
      {open && (
        <tr>
          <td colSpan={10} className="bg-canvas px-3 py-3">
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
              <dt className="text-ink-muted">Status</dt>
              <dd>{item.status_reasons.join("; ")}</dd>
              <dt className="text-ink-muted">OWASP API Top 10</dt>
              <dd>{item.owasp.join(", ")}</dd>
              <dt className="text-ink-muted">Data handled</dt>
              <dd>{item.data}</dd>
              {item.object_rule && (
                <>
                  <dt className="text-ink-muted">Object-level rule</dt>
                  <dd>{item.object_rule}</dd>
                </>
              )}
              <dt className="text-ink-muted">CSRF protection</dt>
              <dd>{item.csrf_protected ? "Origin check and X-SentinelEdge-CSRF header" : "Not needed (bearer token)"}</dd>
              <dt className="text-ink-muted">24-hour breakdown</dt>
              <dd className="tabular-nums">
                {m.client_errors} client errors, {m.server_errors} server errors, {m.unauthenticated} unauthenticated,{" "}
                {m.forbidden} forbidden, {m.throttled} throttled
              </dd>
              <dt className="text-ink-muted">Scanning</dt>
              <dd>{item.scan_note}</dd>
            </dl>
          </td>
        </tr>
      )}
    </>
  );
}

function OwaspSection({ coverage }: { coverage: OwaspCoverage }) {
  return (
    <section aria-labelledby="owasp-heading" className="space-y-3">
      <div>
        <h2 id="owasp-heading" className="text-lg font-semibold">
          {coverage.edition}
        </h2>
        <p className="mt-1 max-w-prose text-sm text-ink-muted">
          How each category is addressed today, what completes it, and the automated tests that prove it. A test fails
          if any cited evidence disappears.
        </p>
      </div>
      <ul className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {coverage.items.map((c) => (
          <OwaspCard key={c.code} category={c} />
        ))}
      </ul>
    </section>
  );
}

function OwaspCard({ category: c }: { category: OwaspCategory }) {
  const s = COVERAGE_STYLE[c.status];
  return (
    <li className="rounded-md border border-line bg-surface p-4">
      <div className="flex items-start justify-between gap-3">
        <h3 className="text-sm font-semibold">
          <span className="font-mono text-accent">{c.code}</span> {c.name}
        </h3>
        <span className={`shrink-0 rounded-sm border px-1.5 py-0.5 text-xs font-medium ${s.className}`}>{s.label}</span>
      </div>
      <p className="mt-1 text-xs text-ink-muted">
        {c.exposed_endpoints} endpoint{c.exposed_endpoints === 1 ? "" : "s"} exposed
      </p>
      <ul className="mt-2 list-disc space-y-1 pl-5 text-sm">
        {c.controls.map((control) => (
          <li key={control}>{control}</li>
        ))}
      </ul>
      {c.planned && (
        <p className="mt-2 text-sm">
          <span className="text-ink-muted">Planned: </span>
          {c.planned}
        </p>
      )}
      <details className="mt-2 text-xs">
        <summary className="cursor-pointer text-accent">Evidence ({c.evidence.length} tests)</summary>
        <ul className="mt-1 space-y-0.5 font-mono text-ink-muted">
          {c.evidence.map((e) => (
            <li key={e} className="break-all">
              {e}
            </li>
          ))}
        </ul>
      </details>
    </li>
  );
}

function ModuleCapabilities() {
  const caps = useCapabilities();
  if (!MODULE) return null;
  return (
    <section aria-labelledby="module-caps" className="space-y-3">
      <h2 id="module-caps" className="text-lg font-semibold">
        Capabilities
      </h2>
      {caps.state === "loading" && <p className="text-sm text-ink-muted">Loading capabilities…</p>}
      {caps.state === "error" && <ErrorPanel error={caps.error} />}
      {caps.state === "ready" && (
        <CapabilityTable
          caption={`Capabilities for ${MODULE.label}`}
          items={caps.data.filter((c) => MODULE.capabilityKeys.includes(c.key))}
        />
      )}
    </section>
  );
}
