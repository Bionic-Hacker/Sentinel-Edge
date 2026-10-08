import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useCurrentUser } from "../../app/auth-context";
import { Button, FormError } from "../../components/forms";
import { ProvenanceBadge } from "../../components/ProvenanceBadge";
import {
  EvidenceText,
  OutcomeText,
  SeverityBadge,
  SimulatedBanner,
  ViewToggle,
  categoryLabel,
  formatTime,
} from "../../components/secops";
import type { ApiError } from "../../lib/api/client";
import { createIncident, getEvent, listEvents, type EventFilters } from "../../lib/api/secops";
import {
  EVENT_CATEGORIES,
  EVENT_SOURCES,
  SEVERITIES,
  type DataView,
  type EventCategory,
  type EventSource,
  type Role,
  type SecurityEventDetail,
  type SecurityEventSummary,
  type Severity,
} from "../../lib/types";
import { asApiError } from "../auth/LoginPage";

const READERS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const INVESTIGATORS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER", "ANALYST"];
const SOURCE_LABEL: Record<EventSource, string> = {
  auth: "Authentication",
  authz: "Authorization",
  rate_limit: "Rate limiter",
  http_analysis: "HTTP analysis",
  audit: "Audit log",
  correlation: "Detection rule",
  waf: "WAF",
  certificate: "Certificate monitor",
  dependency: "Dependency scan",
};

export function ThreatsPage() {
  const user = useCurrentUser();
  return (
    <div className="max-w-7xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Threats</h1>
        <p className="mt-1 max-w-prose text-ink-muted">
          Every security event SentinelEdge recorded: attack patterns found in requests, failed and suspicious sign-ins,
          authorization denials, rate-limit trips, and the detections that correlate them. Select an event for its HTTP
          analysis and evidence.
        </p>
      </header>
      {READERS.includes(user.role) ? (
        <EventsExplorer canInvestigate={INVESTIGATORS.includes(user.role)} />
      ) : (
        <p className="max-w-prose text-ink-muted">
          Security events are available to administrators, security engineers, analysts and viewers.
        </p>
      )}
    </div>
  );
}

function filtersFrom(params: URLSearchParams): EventFilters {
  const filters: EventFilters = { view: params.get("view") === "simulated" ? "simulated" : "live" };
  const category = params.get("category");
  const source = params.get("source");
  const severity = params.get("min_severity");
  const ip = params.get("source_ip");
  if (category && (EVENT_CATEGORIES as readonly string[]).includes(category)) filters.category = category as EventCategory;
  if (source && (EVENT_SOURCES as readonly string[]).includes(source)) filters.source = source as EventSource;
  if (severity && (SEVERITIES as readonly string[]).includes(severity)) filters.min_severity = severity as Severity;
  if (ip && /^[0-9a-fA-F:.]{1,45}$/.test(ip)) filters.source_ip = ip;
  return filters;
}

interface EventPage {
  key: string;
  items: SecurityEventSummary[];
  nextBefore: number | null;
  error: ApiError | null;
}

interface OlderEvents extends EventPage {
  busy: boolean;
}

function EventsExplorer({ canInvestigate }: { canInvestigate: boolean }) {
  const [params, setParams] = useSearchParams();
  const filters = filtersFrom(params);
  const filterKey = params.toString();
  // First page and "load older" pages are separate state, each tagged with the filter key that produced
  // it: loading is derived, and a filter or view change never shows rows from the previous filters.
  const [first, setFirst] = useState<EventPage | null>(null);
  const [older, setOlder] = useState<OlderEvents | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const current = first?.key === filterKey ? first : null;
  const more = older?.key === filterKey ? older : null;
  const loading = current === null;
  const events = [...(current?.items ?? []), ...(more?.items ?? [])];
  const nextBefore = more && more.items.length ? more.nextBefore : (current?.nextBefore ?? null);
  const error = more?.error ?? current?.error ?? null;

  useEffect(() => {
    const controller = new AbortController();
    listEvents(filtersFrom(new URLSearchParams(filterKey)), controller.signal)
      .then((page) => setFirst({ key: filterKey, items: page.items, nextBefore: page.next_before_seq, error: null }))
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setFirst({ key: filterKey, items: [], nextBefore: null, error: asApiError(err) });
      });
    return () => controller.abort();
  }, [filterKey]);

  async function loadOlder(before: number) {
    const base: OlderEvents = more ?? { key: filterKey, items: [], nextBefore: before, busy: false, error: null };
    setOlder({ ...base, busy: true, error: null });
    try {
      const page = await listEvents({ ...filters, before_seq: before });
      setOlder({ key: filterKey, items: [...base.items, ...page.items], nextBefore: page.next_before_seq, busy: false, error: null });
    } catch (err) {
      setOlder({ ...base, busy: false, error: asApiError(err) });
    }
  }

  function setView(view: DataView) {
    const next = new URLSearchParams(params);
    next.set("view", view);
    setSelected(null);
    setParams(next, { replace: true });
  }

  function apply(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const next = new URLSearchParams({ view: filters.view ?? "live" });
    for (const key of ["category", "source", "min_severity", "source_ip"]) {
      const value = String(form.get(key) ?? "").trim();
      if (value) next.set(key, value);
    }
    setSelected(null);
    setParams(next, { replace: true });
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <ViewToggle value={filters.view === "simulated" ? "simulated" : "live"} onChange={setView} />
      </div>
      <form onSubmit={apply} className="flex flex-wrap items-end gap-3" aria-label="Filter security events" key={filterKey}>
        <Select name="category" label="Category" value={filters.category ?? ""} options={EVENT_CATEGORIES.map((c) => [c, categoryLabel(c)])} />
        <Select name="source" label="Source" value={filters.source ?? ""} options={EVENT_SOURCES.map((s) => [s, SOURCE_LABEL[s]])} />
        <Select
          name="min_severity"
          label="Minimum severity"
          value={filters.min_severity ?? ""}
          options={SEVERITIES.map((s) => [s, s])}
        />
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Source IP</span>
          <input
            name="source_ip"
            defaultValue={filters.source_ip ?? ""}
            pattern="[0-9a-fA-F:.]{1,45}"
            className="w-40 rounded border border-line bg-canvas px-2 py-1.5 font-mono text-sm"
          />
        </label>
        <Button type="submit">Apply</Button>
        <Button
          type="button"
          variant="secondary"
          onClick={() => {
            setSelected(null);
            setParams(new URLSearchParams({ view: filters.view ?? "live" }), { replace: true });
          }}
        >
          Reset
        </Button>
      </form>

      {filters.view === "simulated" && <SimulatedBanner />}
      {error && <FormError error={error} />}

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <div className="overflow-x-auto rounded-md border border-line">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Security events, newest first</caption>
            <thead className="bg-surface text-xs text-ink-muted">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">Time</th>
                <th scope="col" className="px-3 py-2 font-medium">Severity</th>
                <th scope="col" className="px-3 py-2 font-medium">Event</th>
                <th scope="col" className="px-3 py-2 font-medium">Outcome</th>
                <th scope="col" className="px-3 py-2 font-medium">Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {events.map((e) => (
                <tr key={e.id} className={selected === e.id ? "bg-raised" : undefined}>
                  <td className="whitespace-nowrap px-3 py-2 text-xs tabular-nums text-ink-muted">{formatTime(e.occurred_at)}</td>
                  <td className="px-3 py-2">
                    <SeverityBadge severity={e.severity} />
                  </td>
                  <td className="px-3 py-2">
                    <button
                      type="button"
                      onClick={() => setSelected(e.id)}
                      aria-pressed={selected === e.id}
                      className="text-left text-accent hover:underline"
                    >
                      {e.title}
                    </button>
                    <span className="block text-xs text-ink-muted">
                      {categoryLabel(e.category)} · {SOURCE_LABEL[e.source]}
                      {e.rule_id ? ` · ${e.rule_id}` : ""}
                      {e.incident_id ? " · in an incident" : ""}
                    </span>
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs">
                    <OutcomeText outcome={e.outcome} />
                    {e.status_code !== null && <span className="ml-1 text-ink-muted">({e.status_code})</span>}
                  </td>
                  <td className="px-3 py-2 text-xs">
                    <span className="font-mono">{e.source_ip ?? "–"}</span>
                    {e.actor_label && <span className="block text-ink-muted">{e.actor_label}</span>}
                  </td>
                </tr>
              ))}
              {loading && (
                <tr>
                  <td colSpan={5} className="px-3 py-6 text-center text-ink-muted">
                    Loading security events…
                  </td>
                </tr>
              )}
              {!events.length && !loading && !error && (
                <tr>
                  <td colSpan={5} className="px-3 py-6 text-center text-ink-muted">
                    No security events match these filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
          {nextBefore !== null && (
            <div className="border-t border-line p-3">
              <Button variant="secondary" busy={more?.busy ?? false} onClick={() => void loadOlder(nextBefore)}>
                Load older events
              </Button>
            </div>
          )}
        </div>
        <aside aria-label="Event detail" className="xl:sticky xl:top-4 xl:self-start">
          {selected ? (
            <EventDetail key={selected} eventId={selected} canInvestigate={canInvestigate} />
          ) : (
            <p className="rounded-md border border-dashed border-line p-5 text-sm text-ink-muted">
              Select an event to see its HTTP analysis, evidence and the incident it belongs to.
            </p>
          )}
        </aside>
      </div>
    </div>
  );
}

function Select({
  name,
  label,
  value,
  options,
}: {
  name: string;
  label: string;
  value: string;
  options: [string, string][];
}) {
  return (
    <label className="space-y-1 text-sm">
      <span className="block text-ink-muted">{label}</span>
      <select name={name} defaultValue={value} className="rounded border border-line bg-canvas px-2 py-1.5 text-sm capitalize">
        <option value="">Any</option>
        {options.map(([v, text]) => (
          <option key={v} value={v}>
            {text}
          </option>
        ))}
      </select>
    </label>
  );
}

interface Finding {
  rule_id: string;
  description?: string;
  location?: string;
  field?: string | null;
  snippet?: string;
}

function findingsOf(evidence: Record<string, unknown>): Finding[] {
  const raw = evidence.findings;
  if (!Array.isArray(raw)) return [];
  return raw.filter(
    (f): f is Finding => typeof f === "object" && f !== null && typeof (f as { rule_id?: unknown }).rule_id === "string",
  );
}

function EventDetail({ eventId, canInvestigate }: { eventId: string; canInvestigate: boolean }) {
  const navigate = useNavigate();
  // Rendered with key={eventId}, so a new selection mounts a fresh panel: no reset in the effect.
  const [event, setEvent] = useState<SecurityEventDetail | null>(null);
  const [loadError, setLoadError] = useState<ApiError | null>(null);
  // A failed "open incident" is reported under its button and leaves the event on screen.
  const [actionError, setActionError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    getEvent(eventId, controller.signal)
      .then(setEvent)
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setLoadError(asApiError(err));
      });
    return () => controller.abort();
  }, [eventId]);

  async function openIncident(e: SecurityEventDetail) {
    setBusy(true);
    setActionError(null);
    try {
      const incident = await createIncident({
        title: e.title.slice(0, 160),
        severity: e.severity,
        category: e.category,
        event_ids: [e.id],
      });
      void navigate(`/incidents/${incident.id}`);
    } catch (err) {
      setActionError(asApiError(err));
      setBusy(false);
    }
  }

  if (loadError) return <FormError error={loadError} />;
  if (!event) return <p className="text-sm text-ink-muted">Loading the event…</p>;
  const findings = findingsOf(event.evidence);
  const request = [
    ["Request", event.method && event.endpoint ? `${event.method} ${event.endpoint}` : null],
    ["Response", event.status_code !== null ? String(event.status_code) : null],
    ["Source IP", event.source_ip],
    ["Account", event.actor_label],
    ["User agent", event.user_agent],
    ["Correlation ID", event.correlation_id],
  ].filter((row): row is [string, string] => row[1] !== null);

  return (
    <article className="space-y-5 rounded-md border border-line bg-surface p-5">
      <header className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={event.severity} />
          <ProvenanceBadge provenance={event.provenance} />
          <span className="text-xs text-ink-muted">{formatTime(event.occurred_at)}</span>
        </div>
        <h2 className="text-base font-semibold">{event.title}</h2>
        <p className="text-sm text-ink-muted">
          {categoryLabel(event.category)} recorded by {SOURCE_LABEL[event.source].toLowerCase()}
          {event.rule_id ? ` (rule ${event.rule_id})` : ""}. Outcome: <OutcomeText outcome={event.outcome} />.
        </p>
      </header>

      {request.length > 0 && (
        <section aria-labelledby={`req-${event.id}`}>
          <h3 id={`req-${event.id}`} className="mb-2 text-sm font-medium">
            HTTP analysis
          </h3>
          <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
            {request.map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-ink-muted">{k}</dt>
                <dd className="break-all font-mono text-xs leading-5">{v}</dd>
              </div>
            ))}
          </dl>
        </section>
      )}

      {findings.length > 0 && (
        <section aria-labelledby={`find-${event.id}`} className="space-y-2">
          <h3 id={`find-${event.id}`} className="text-sm font-medium">
            What matched
          </h3>
          <ul className="space-y-2">
            {findings.map((f) => (
              <li key={`${f.rule_id}-${f.field ?? ""}`} className="rounded border border-line p-2 text-sm">
                <span className="font-medium">{f.rule_id}</span>
                {f.description && <span className="text-ink-muted"> · {f.description}</span>}
                <span className="block text-xs text-ink-muted">
                  In {f.location ?? "request"}
                  {f.field ? ` field "${f.field}"` : ""}
                </span>
                {/* Attacker-written text: shown as text, never interpreted. */}
                {f.snippet && <code className="mt-1 block break-all rounded bg-canvas px-2 py-1 font-mono text-xs">{f.snippet}</code>}
              </li>
            ))}
          </ul>
          <p className="text-xs text-ink-muted">
            Detect-only: SentinelEdge recorded the attempt; the request was handled by the application's own controls.
          </p>
        </section>
      )}

      <section className="space-y-2">
        <h3 className="text-sm font-medium">Evidence</h3>
        <EvidenceText value={event.evidence} />
      </section>

      <footer className="flex flex-wrap items-center gap-3">
        {event.incident_id ? (
          <Link to={`/incidents/${event.incident_id}`} className="text-sm text-accent hover:underline">
            Open the incident this event belongs to
          </Link>
        ) : canInvestigate ? (
          <Button busy={busy} onClick={() => void openIncident(event)}>
            Open an incident from this event
          </Button>
        ) : (
          <span className="text-sm text-ink-muted">Not part of an incident.</span>
        )}
        {actionError && (
          <div className="w-full">
            <FormError error={actionError} />
          </div>
        )}
      </footer>
    </article>
  );
}
