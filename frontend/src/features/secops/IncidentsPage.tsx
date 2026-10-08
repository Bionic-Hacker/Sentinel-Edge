import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useCurrentUser } from "../../app/auth-context";
import { Button, FormError } from "../../components/forms";
import { ProvenanceBadge } from "../../components/ProvenanceBadge";
import {
  IncidentStatusBadge,
  SeverityBadge,
  SimulatedBanner,
  ViewToggle,
  formatTime,
  statusLabel,
} from "../../components/secops";
import type { ApiError } from "../../lib/api/client";
import { createIncident, listIncidents, type IncidentFilters } from "../../lib/api/secops";
import { INCIDENT_STATUSES, SEVERITIES, type DataView, type IncidentSummary, type Role, type Severity } from "../../lib/types";
import { asApiError } from "../auth/LoginPage";

const READERS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const INVESTIGATORS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER", "ANALYST"];
const STATES = ["open", "closed", "all", ...INCIDENT_STATUSES] as const;

export function IncidentsPage() {
  const user = useCurrentUser();
  return (
    <div className="max-w-7xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Incidents</h1>
        <p className="mt-1 max-w-prose text-ink-muted">
          Detection to closure: DETECTED, TRIAGED, INVESTIGATING, CONTAINMENT, REMEDIATION, VALIDATION, CLOSED. Every
          change is a timeline entry committed to the tamper-evident audit log.
        </p>
      </header>
      {READERS.includes(user.role) ? (
        <IncidentList canCreate={INVESTIGATORS.includes(user.role)} />
      ) : (
        <p className="max-w-prose text-ink-muted">
          Incidents are available to administrators, security engineers, analysts and viewers.
        </p>
      )}
    </div>
  );
}

function filtersFrom(params: URLSearchParams): IncidentFilters & { view: DataView } {
  const state = params.get("state");
  const owner = params.get("owner");
  const severity = params.get("min_severity");
  const filters: IncidentFilters & { view: DataView } = {
    view: params.get("view") === "simulated" ? "simulated" : "live",
    state: state && (STATES as readonly string[]).includes(state) ? (state as IncidentFilters["state"] & string) : "open",
  };
  if (owner === "me" || owner === "unassigned") filters.owner = owner;
  if (severity && (SEVERITIES as readonly string[]).includes(severity)) filters.min_severity = severity as Severity;
  return filters;
}

interface FirstPage {
  key: string;
  items: IncidentSummary[];
  nextBefore: number | null;
  error: ApiError | null;
}

interface OlderPages extends FirstPage {
  busy: boolean;
}

function IncidentList({ canCreate }: { canCreate: boolean }) {
  const [params, setParams] = useSearchParams();
  const key = params.toString();
  const filters = filtersFrom(params);
  // The first page and the "load older" pages are separate state, each tagged with the filter key that
  // produced it, so a filter change shows only rows that match the filters on screen.
  const [first, setFirst] = useState<FirstPage | null>(null);
  const [older, setOlder] = useState<OlderPages | null>(null);
  const [creating, setCreating] = useState(false);
  const current = first?.key === key ? first : null;
  const more = older?.key === key ? older : null;
  const loading = current === null;
  const items = [...(current?.items ?? []), ...(more?.items ?? [])];
  const nextBefore = more && more.items.length ? more.nextBefore : (current?.nextBefore ?? null);
  const error = more?.error ?? current?.error ?? null;

  useEffect(() => {
    const controller = new AbortController();
    listIncidents(filtersFrom(new URLSearchParams(key)), controller.signal)
      .then((page) => setFirst({ key, items: page.items, nextBefore: page.next_before_number, error: null }))
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setFirst({ key, items: [], nextBefore: null, error: asApiError(err) });
      });
    return () => controller.abort();
  }, [key]);

  function set(name: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(name, value);
    else next.delete(name);
    setParams(next, { replace: true });
  }

  async function loadOlder(before: number) {
    const base: OlderPages = more ?? { key, items: [], nextBefore: before, busy: false, error: null };
    setOlder({ ...base, busy: true, error: null });
    try {
      const page = await listIncidents({ ...filters, before_number: before });
      setOlder({ key, items: [...base.items, ...page.items], nextBefore: page.next_before_number, busy: false, error: null });
    } catch (err) {
      setOlder({ ...base, busy: false, error: asApiError(err) });
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end gap-3">
        <ViewToggle value={filters.view} onChange={(v) => set("view", v)} />
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Status</span>
          <select
            value={filters.state ?? "open"}
            onChange={(e) => set("state", e.target.value)}
            className="rounded border border-line bg-canvas px-2 py-1.5 text-sm"
          >
            <option value="open">Open</option>
            <option value="closed">Closed</option>
            <option value="all">All</option>
            {INCIDENT_STATUSES.map((s) => (
              <option key={s} value={s}>
                {statusLabel(s)} only
              </option>
            ))}
          </select>
        </label>
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Owner</span>
          <select
            value={filters.owner ?? ""}
            onChange={(e) => set("owner", e.target.value)}
            className="rounded border border-line bg-canvas px-2 py-1.5 text-sm"
          >
            <option value="">Anyone</option>
            <option value="me">Assigned to me</option>
            <option value="unassigned">Unassigned</option>
          </select>
        </label>
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Minimum severity</span>
          <select
            value={filters.min_severity ?? ""}
            onChange={(e) => set("min_severity", e.target.value)}
            className="rounded border border-line bg-canvas px-2 py-1.5 text-sm capitalize"
          >
            <option value="">Any</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        {canCreate && !creating && (
          <Button className="ml-auto" onClick={() => setCreating(true)}>
            New incident
          </Button>
        )}
      </div>
      {creating && <NewIncidentForm onCancel={() => setCreating(false)} />}
      {filters.view === "simulated" && <SimulatedBanner />}
      {error && <FormError error={error} />}

      <div className="overflow-x-auto rounded-md border border-line">
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Incidents, newest first</caption>
          <thead className="bg-surface text-xs text-ink-muted">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">Incident</th>
              <th scope="col" className="px-3 py-2 font-medium">Severity</th>
              <th scope="col" className="px-3 py-2 font-medium">Status</th>
              <th scope="col" className="px-3 py-2 font-medium">Owner</th>
              <th scope="col" className="px-3 py-2 font-medium">Evidence</th>
              <th scope="col" className="px-3 py-2 font-medium">Detected</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {items.map((i) => (
              <tr key={i.id}>
                <td className="px-3 py-2">
                  <Link to={`/incidents/${i.id}`} className="text-accent hover:underline">
                    {i.reference}: {i.title}
                  </Link>
                  <span className="mt-0.5 flex items-center gap-2 text-xs text-ink-muted">
                    <ProvenanceBadge provenance={i.provenance} />
                    {i.source_ip && <span className="font-mono">{i.source_ip}</span>}
                    {i.detection_rule && <span>{i.detection_rule}</span>}
                  </span>
                </td>
                <td className="px-3 py-2">
                  <SeverityBadge severity={i.severity} />
                </td>
                <td className="px-3 py-2">
                  <IncidentStatusBadge status={i.status} />
                  {i.resolution && <span className="block text-xs text-ink-muted">{i.resolution.replace("_", " ")}</span>}
                </td>
                <td className="px-3 py-2 text-ink-muted">{i.owner?.display_name ?? "Unassigned"}</td>
                <td className="px-3 py-2 tabular-nums text-ink-muted">{i.event_count} events</td>
                <td className="whitespace-nowrap px-3 py-2 text-xs tabular-nums text-ink-muted">{formatTime(i.detected_at)}</td>
              </tr>
            ))}
            {loading && (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-center text-ink-muted">
                  Loading incidents…
                </td>
              </tr>
            )}
            {!items.length && !loading && !error && (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-center text-ink-muted">
                  No incidents match these filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {nextBefore !== null && (
          <div className="border-t border-line p-3">
            <Button variant="secondary" busy={more?.busy ?? false} onClick={() => void loadOlder(nextBefore)}>
              Load older incidents
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}

function NewIncidentForm({ onCancel }: { onCancel: () => void }) {
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const summary = String(form.get("summary") ?? "").trim();
      const incident = await createIncident({
        title: String(form.get("title") ?? "").trim(),
        severity: String(form.get("severity")) as Severity,
        ...(summary ? { summary } : {}),
      });
      void navigate(`/incidents/${incident.id}`);
    } catch (err) {
      setError(asApiError(err));
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="space-y-3 rounded-md border border-line bg-surface p-5" aria-label="New incident">
      <h2 className="text-base font-semibold">New incident</h2>
      <p className="text-sm text-ink-muted">
        You will own it. To attach evidence, open it from an event on the Threats page or add events later.
      </p>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-[minmax(0,3fr)_minmax(0,1fr)]">
        <label className="space-y-1 text-sm">
          <span className="block font-medium">Title</span>
          <input name="title" required maxLength={160} className="w-full rounded border border-line bg-canvas px-3 py-2 text-sm" />
        </label>
        <label className="space-y-1 text-sm">
          <span className="block font-medium">Severity</span>
          <select name="severity" defaultValue="medium" className="w-full rounded border border-line bg-canvas px-3 py-2 text-sm capitalize">
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
      </div>
      <label className="block space-y-1 text-sm">
        <span className="block font-medium">Summary</span>
        <textarea name="summary" maxLength={2000} rows={3} className="w-full rounded border border-line bg-canvas px-3 py-2 text-sm" />
      </label>
      <FormError error={error} />
      <div className="flex gap-2">
        <Button type="submit" busy={busy}>
          Open incident
        </Button>
        <Button type="button" variant="secondary" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}
