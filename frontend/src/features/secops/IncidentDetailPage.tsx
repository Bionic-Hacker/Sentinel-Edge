import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { useCurrentUser } from "../../app/auth-context";
import { Button, FormError, Notice } from "../../components/forms";
import { ProvenanceBadge } from "../../components/ProvenanceBadge";
import {
  IncidentStatusBadge,
  OutcomeText,
  SeverityBadge,
  SimulatedBanner,
  categoryLabel,
  formatTime,
  statusLabel,
} from "../../components/secops";
import type { ApiError } from "../../lib/api/client";
import {
  addIncidentNote,
  assignIncident,
  getIncident,
  listAssignees,
  transitionIncident,
  updateIncident,
} from "../../lib/api/secops";
import {
  INCIDENT_STATUSES,
  SEVERITIES,
  type AvailableMove,
  type IncidentDetail,
  type Person,
  type Resolution,
  type Role,
  type Severity,
  type TimelineEntry,
} from "../../lib/types";
import { asApiError } from "../auth/LoginPage";
import { AnalyzePanel } from "../ai/ai";

const READERS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const RESOLUTION_LABEL: Record<Resolution, string> = {
  resolved: "Resolved (remediated and validated)",
  accepted_risk: "Accepted risk (validated, residual risk accepted)",
  false_positive: "False positive (not an attack)",
  duplicate: "Duplicate (tracked in another incident)",
};

export function IncidentDetailPage() {
  const user = useCurrentUser();
  const { incidentId = "" } = useParams();
  if (!READERS.includes(user.role)) {
    return <p className="max-w-prose text-ink-muted">Incidents are available to administrators, security engineers, analysts and viewers.</p>;
  }
  return <IncidentView key={incidentId} incidentId={incidentId} />;
}

function IncidentView({ incidentId }: { incidentId: string }) {
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  // Set when a write was rejected with 409 stale_version: someone else changed the incident.
  const [stale, setStale] = useState(false);
  const [reloading, setReloading] = useState(false);

  const reload = useCallback(
    (signal?: AbortSignal) =>
      getIncident(incidentId, signal)
        .then((i) => {
          setIncident(i);
          setError(null);
        })
        .catch((err: unknown) => {
          if (!signal?.aborted) setError(asApiError(err));
        }),
    [incidentId],
  );

  useEffect(() => {
    const controller = new AbortController();
    void reload(controller.signal);
    return () => controller.abort();
  }, [reload]);

  if (error && !incident) {
    return (
      <div className="space-y-3">
        <Link to="/incidents" className="text-sm text-accent hover:underline">
          All incidents
        </Link>
        <FormError error={error} />
      </div>
    );
  }
  if (!incident) return <p className="text-sm text-ink-muted">Loading the incident…</p>;

  const simulated = incident.provenance === "SIMULATED" || incident.provenance === "DEMO";
  return (
    <div className="max-w-7xl space-y-6">
      <header className="space-y-3">
        <Link to={`/incidents?view=${simulated ? "simulated" : "live"}`} className="text-sm text-accent hover:underline">
          All incidents
        </Link>
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-sm text-ink-muted">{incident.reference}</span>
          <SeverityBadge severity={incident.severity} />
          <IncidentStatusBadge status={incident.status} />
          <ProvenanceBadge provenance={incident.provenance} />
          {incident.resolution && <span className="text-sm text-ink-muted">{RESOLUTION_LABEL[incident.resolution]}</span>}
        </div>
        <h1 className="text-2xl font-semibold tracking-tight">{incident.title}</h1>
        <p className="text-sm text-ink-muted">
          Detected {formatTime(incident.detected_at)} · opened by {incident.created_by_label} · owner{" "}
          {incident.owner ? `${incident.owner.display_name} (${incident.owner.role.replace("_", " ").toLowerCase()})` : "none"}
          {incident.category ? ` · ${categoryLabel(incident.category)}` : ""}
        </p>
      </header>
      <AnalyzePanel subjectType="incident" subjectId={incident.id} />
      {simulated && (
        <SimulatedBanner>
          This incident was opened from attack-simulator output. Work it like a real one to practise the workflow; its
          evidence can only ever be simulated.
        </SimulatedBanner>
      )}
      <Workflow incident={incident} />
      {error && <FormError error={error} />}
      {stale && (
        <div role="alert" className="flex flex-wrap items-center gap-3 rounded border border-prov-sim/60 bg-prov-sim/10 px-3 py-2 text-sm">
          <span className="min-w-0 flex-1">
            This incident changed since you loaded it, so your change was not saved. Reload to see the latest version,
            then try again.
          </span>
          <Button
            variant="secondary"
            busy={reloading}
            onClick={() => {
              setReloading(true);
              void reload().finally(() => {
                setReloading(false);
                setStale(false);
              });
            }}
          >
            Reload
          </Button>
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <div className="space-y-6">
          <Actions incident={incident} onChange={setIncident} onStale={() => setStale(true)} />
          <Details incident={incident} onChange={setIncident} onStale={() => setStale(true)} />
          <Evidence incident={incident} />
          <Timeline incident={incident} onChange={setIncident} />
        </div>
        <div className="space-y-6">
          <Risk incident={incident} />
          <IntegrityPanel incident={incident} />
          <Trigger incident={incident} />
          <section className="rounded-md border border-dashed border-line p-5">
            <h2 className="text-base font-semibold">AI analysis</h2>
            <p className="mt-2 text-sm text-ink-muted">
              Arrives in Phase 9: Amazon Bedrock analysis that separates observed evidence from inference, with human
              approval for any proposed action.
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}

function Workflow({ incident }: { incident: IncidentDetail }) {
  const current = INCIDENT_STATUSES.indexOf(incident.status);
  return (
    <nav aria-label="Incident workflow">
      <ol className="flex flex-wrap gap-1">
        {INCIDENT_STATUSES.map((status, i) => {
          const done = i < current;
          const here = i === current;
          return (
            <li
              key={status}
              aria-current={here ? "step" : undefined}
              className={`rounded-sm border px-2.5 py-1 text-xs ${
                here ? "border-accent bg-accent/15 text-ink" : done ? "border-line text-ink" : "border-line text-ink-muted"
              }`}
            >
              {done && <span aria-hidden="true">✓ </span>}
              {statusLabel(status)}
              {done && <span className="sr-only"> (done)</span>}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-3 rounded-md border border-line bg-surface p-5">
      <h2 className="text-base font-semibold">{title}</h2>
      {children}
    </section>
  );
}

function Actions({
  incident,
  onChange,
  onStale,
}: {
  incident: IncidentDetail;
  onChange: (i: IncidentDetail) => void;
  onStale: () => void;
}) {
  const user = useCurrentUser();
  const p = incident.permissions;
  const [pending, setPending] = useState<AvailableMove | null>(null);
  const [formProblem, setFormProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [assignees, setAssignees] = useState<Person[] | null>(null);

  useEffect(() => {
    if (!p.can_assign) return;
    const controller = new AbortController();
    listAssignees(controller.signal)
      .then(setAssignees)
      .catch(() => setAssignees([]));
    return () => controller.abort();
  }, [p.can_assign]);

  if (!p.moves.length && !p.can_take && !p.can_assign) {
    return (
      <Panel title="Actions">
        <p className="text-sm text-ink-muted">
          {incident.status === "CLOSED"
            ? "Closed. A security engineer or admin can reopen it."
            : "You can read this incident. Its owner, a security engineer or an admin can move it forward."}
        </p>
      </Panel>
    );
  }

  async function run(action: () => Promise<IncidentDetail>) {
    setBusy(true);
    setError(null);
    try {
      onChange(await action());
      setPending(null);
    } catch (err) {
      const apiError = asApiError(err);
      if (apiError.code === "stale_version") onStale();
      else setError(apiError);
    } finally {
      setBusy(false);
    }
  }

  function move(m: AvailableMove) {
    setFormProblem(null);
    if (m.note_required || m.resolutions.length) setPending(m);
    else void run(() => transitionIncident(incident.id, { version: incident.version, to_status: m.to_status }));
  }

  function submitMove(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!pending) return;
    const form = new FormData(event.currentTarget);
    const note = String(form.get("note") ?? "").trim();
    const resolution = String(form.get("resolution") ?? "");
    // The API enforces these too; checking first keeps the form open with a clear reason.
    if (pending.note_required && !note) {
      setFormProblem("Add a note explaining this decision.");
      return;
    }
    if (pending.resolutions.length && !resolution) {
      setFormProblem("Choose a resolution.");
      return;
    }
    setFormProblem(null);
    void run(() =>
      transitionIncident(incident.id, {
        version: incident.version,
        to_status: pending.to_status,
        ...(note ? { note } : {}),
        ...(resolution ? { resolution: resolution as Resolution } : {}),
      }),
    );
  }

  return (
    <Panel title="Actions">
      <div className="flex flex-wrap gap-2">
        {p.moves.map((m) => (
          <Button
            key={`${m.to_status}-${m.label}`}
            variant={m.to_status === "CLOSED" || m.label === "Validation failed" ? "secondary" : "primary"}
            busy={busy}
            onClick={() => move(m)}
          >
            {m.label}
          </Button>
        ))}
        {p.can_take && (
          <Button
            variant="secondary"
            busy={busy}
            onClick={() => void run(() => assignIncident(incident.id, { version: incident.version, owner_id: user.id }))}
          >
            Take this incident
          </Button>
        )}
      </div>
      {pending && (
        <form noValidate onSubmit={submitMove} className="space-y-3 rounded border border-line p-3" aria-label={pending.label}>
          {pending.resolutions.length > 0 && (
            <label className="block space-y-1 text-sm">
              <span className="block font-medium">Resolution</span>
              <select name="resolution" required className="w-full rounded border border-line bg-canvas px-3 py-2 text-sm">
                {pending.resolutions.map((r) => (
                  <option key={r} value={r}>
                    {RESOLUTION_LABEL[r]}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label className="block space-y-1 text-sm">
            <span className="block font-medium">Note{pending.note_required ? "" : " (optional)"}</span>
            <textarea
              name="note"
              required={pending.note_required}
              maxLength={2000}
              rows={3}
              aria-invalid={formProblem ? true : undefined}
              className="w-full rounded border border-line bg-canvas px-3 py-2 text-sm"
            />
          </label>
          {formProblem && (
            <p role="alert" className="text-sm text-fail">
              {formProblem}
            </p>
          )}
          <div className="flex gap-2">
            <Button type="submit" busy={busy}>
              {pending.label}
            </Button>
            <Button type="button" variant="secondary" onClick={() => setPending(null)}>
              Cancel
            </Button>
          </div>
        </form>
      )}
      {p.can_assign && assignees && (
        <label className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-ink-muted">Owner</span>
          <select
            value={incident.owner?.id ?? ""}
            disabled={busy}
            onChange={(e) =>
              void run(() =>
                assignIncident(incident.id, { version: incident.version, owner_id: e.target.value || null }),
              )
            }
            className="min-w-0 max-w-full rounded border border-line bg-canvas px-2 py-1.5 text-sm"
          >
            <option value="">Unassigned</option>
            {assignees.map((a) => (
              <option key={a.id} value={a.id}>
                {a.display_name} ({a.role.replace("_", " ").toLowerCase()})
              </option>
            ))}
          </select>
        </label>
      )}
      <FormError error={error} />
    </Panel>
  );
}

function Details({
  incident,
  onChange,
  onStale,
}: {
  incident: IncidentDetail;
  onChange: (i: IncidentDetail) => void;
  onStale: () => void;
}) {
  const p = incident.permissions;
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const body: { version: number; title?: string; summary?: string; remediation?: string; severity?: Severity } = {
      version: incident.version,
      title: String(form.get("title") ?? "").trim(),
      summary: String(form.get("summary") ?? "").trim(),
      remediation: String(form.get("remediation") ?? "").trim(),
    };
    if (p.can_change_severity) body.severity = String(form.get("severity")) as Severity;
    setBusy(true);
    setError(null);
    try {
      onChange(await updateIncident(incident.id, body));
      setEditing(false);
    } catch (err) {
      const apiError = asApiError(err);
      if (apiError.code === "stale_version") onStale();
      else setError(apiError);
    } finally {
      setBusy(false);
    }
  }

  if (editing) {
    return (
      <Panel title="Details">
        <form onSubmit={(e) => void save(e)} className="space-y-3" aria-label="Edit incident">
          <label className="block space-y-1 text-sm">
            <span className="block font-medium">Title</span>
            <input name="title" defaultValue={incident.title} required maxLength={160} className="w-full rounded border border-line bg-canvas px-3 py-2 text-sm" />
          </label>
          {p.can_change_severity && (
            <label className="block space-y-1 text-sm">
              <span className="block font-medium">Severity</span>
              <select name="severity" defaultValue={incident.severity} className="rounded border border-line bg-canvas px-3 py-2 text-sm capitalize">
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label className="block space-y-1 text-sm">
            <span className="block font-medium">Summary</span>
            <textarea name="summary" defaultValue={incident.summary} maxLength={2000} rows={4} className="w-full rounded border border-line bg-canvas px-3 py-2 text-sm" />
          </label>
          <label className="block space-y-1 text-sm">
            <span className="block font-medium">Remediation</span>
            <textarea
              name="remediation"
              defaultValue={incident.remediation ?? ""}
              maxLength={4000}
              rows={4}
              className="w-full rounded border border-line bg-canvas px-3 py-2 text-sm"
            />
          </label>
          <FormError error={error} />
          <div className="flex gap-2">
            <Button type="submit" busy={busy}>
              Save
            </Button>
            <Button type="button" variant="secondary" onClick={() => setEditing(false)}>
              Cancel
            </Button>
          </div>
        </form>
      </Panel>
    );
  }
  return (
    <Panel title="Details">
      {/* Analyst-written text: rendered as text, line breaks kept. */}
      <p className="whitespace-pre-wrap text-sm">{incident.summary || "No summary yet."}</p>
      <h3 className="text-sm font-medium">Remediation</h3>
      <p className="whitespace-pre-wrap text-sm text-ink-muted">
        {incident.remediation || "Not recorded yet. Closing as resolved requires it."}
      </p>
      {p.can_edit && (
        <Button variant="secondary" onClick={() => setEditing(true)}>
          Edit details
        </Button>
      )}
    </Panel>
  );
}

function Evidence({ incident }: { incident: IncidentDetail }) {
  return (
    <Panel title={`Evidence (${incident.event_count} events)`}>
      {incident.events.length ? (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Security events linked to this incident</caption>
            <thead className="text-xs text-ink-muted">
              <tr>
                <th scope="col" className="pb-2 font-medium">Time</th>
                <th scope="col" className="pb-2 font-medium">Event</th>
                <th scope="col" className="pb-2 font-medium">Outcome</th>
                <th scope="col" className="pb-2 font-medium">Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {incident.events.map((e) => (
                <tr key={e.id}>
                  <td className="whitespace-nowrap py-2 pr-3 text-xs tabular-nums text-ink-muted">{formatTime(e.occurred_at)}</td>
                  <td className="py-2 pr-3">
                    <span className="flex items-center gap-2">
                      <SeverityBadge severity={e.severity} />
                      <span>{e.title}</span>
                    </span>
                    <span className="block text-xs text-ink-muted">
                      {categoryLabel(e.category)}
                      {e.rule_id ? ` · ${e.rule_id}` : ""}
                      {e.method && e.endpoint ? ` · ${e.method} ${e.endpoint}` : ""}
                    </span>
                  </td>
                  <td className="whitespace-nowrap py-2 pr-3 text-xs">
                    <OutcomeText outcome={e.outcome} />
                  </td>
                  <td className="py-2 font-mono text-xs">
                    {e.source_ip ? (
                      <Link
                        to={`/threats?source_ip=${encodeURIComponent(e.source_ip)}&view=${
                          e.provenance === "SIMULATED" || e.provenance === "DEMO" ? "simulated" : "live"
                        }`}
                        className="text-accent hover:underline"
                      >
                        {e.source_ip}
                      </Link>
                    ) : (
                      "–"
                    )}
                    {e.actor_label && <span className="block font-sans text-ink-muted">{e.actor_label}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-sm text-ink-muted">No events linked yet. Open one from the Threats page to attach it.</p>
      )}
      <p className="text-xs text-ink-muted">
        Evidence links are write-once: an event can belong to one incident and can never be moved or detached.
      </p>
    </Panel>
  );
}

function describe(entry: TimelineEntry): string {
  const d = entry.details;
  switch (entry.kind) {
    case "created":
      return d.manual ? "Opened the incident" : `Opened automatically${typeof d.rule === "string" ? ` by rule ${d.rule}` : ""}`;
    case "status_changed":
      return `${entry.from_status ? statusLabel(entry.from_status) : "?"} → ${entry.to_status ? statusLabel(entry.to_status) : "?"}${
        typeof d.resolution === "string" ? ` (${d.resolution.replace("_", " ")})` : ""
      }`;
    case "assigned":
      return typeof d.owner === "string" ? `Assigned to ${d.owner}` : "Unassigned";
    case "events_linked":
      return `Linked ${typeof d.count === "number" ? d.count : "some"} event(s) as evidence`;
    case "severity_raised":
      return `Severity raised ${typeof d.from === "string" ? d.from : ""} → ${typeof d.to === "string" ? d.to : ""}`;
    case "updated":
      return `Updated ${Array.isArray(d.fields) ? d.fields.join(", ") : "details"}${typeof d.severity === "string" ? ` (severity ${d.severity})` : ""}`;
    case "note":
      return "Added a note";
  }
}

function Timeline({ incident, onChange }: { incident: IncidentDetail; onChange: (i: IncidentDetail) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [added, setAdded] = useState(false);

  async function addNote(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const body = String(new FormData(formElement).get("body") ?? "").trim();
    if (!body) return;
    setBusy(true);
    setError(null);
    setAdded(false);
    try {
      onChange(await addIncidentNote(incident.id, body));
      formElement.reset();
      setAdded(true);
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel title="Timeline">
      <ol className="space-y-3">
        {incident.timeline.map((t) => (
          <li key={t.id} className="border-l-2 border-line pl-3">
            <p className="text-sm">
              <span className="font-medium">{t.actor_label}</span> <span className="text-ink-muted">{describe(t)}</span>
            </p>
            <p className="text-xs tabular-nums text-ink-muted">{formatTime(t.at)}</p>
            {t.body && <p className="mt-1 whitespace-pre-wrap rounded bg-canvas px-3 py-2 text-sm">{t.body}</p>}
          </li>
        ))}
      </ol>
      {incident.permissions.can_add_note && (
        <form onSubmit={(e) => void addNote(e)} className="space-y-2" aria-label="Add a note">
          <label className="block space-y-1 text-sm">
            <span className="block font-medium">Add a note</span>
            <textarea name="body" required maxLength={4000} rows={3} className="w-full rounded border border-line bg-canvas px-3 py-2 text-sm" />
          </label>
          <p className="text-xs text-ink-muted">Notes cannot be edited or deleted: correct a note by adding another.</p>
          <FormError error={error} />
          {added && <Notice>Note added.</Notice>}
          <Button type="submit" busy={busy}>
            Add note
          </Button>
        </form>
      )}
    </Panel>
  );
}

function Risk({ incident }: { incident: IncidentDetail }) {
  return (
    <Panel title="Risk score">
      <p className="text-3xl font-semibold [font-feature-settings:'tnum'_0]">
        {incident.risk.score}
        <span className="text-base font-normal text-ink-muted"> / 100</span>
      </p>
      <ul className="space-y-1 text-sm">
        {incident.risk.factors.map((f) => (
          <li key={f.reason} className="flex justify-between gap-3">
            <span className="text-ink-muted">{f.reason}</span>
            <span className="tabular-nums">+{f.points}</span>
          </li>
        ))}
      </ul>
      <p className="text-xs text-ink-muted">The score is the sum of these factors, capped at 100.</p>
    </Panel>
  );
}

function IntegrityPanel({ incident }: { incident: IncidentDetail }) {
  const i = incident.integrity;
  return (
    <Panel title="Evidence integrity">
      {i.verified ? (
        <p className="text-sm">
          <span className="font-medium text-ok">Verified.</span> All {i.entries_checked} timeline entries match the
          digests committed to the hash-chained audit log.
        </p>
      ) : (
        <p role="alert" className="text-sm">
          <span className="font-medium text-fail">Mismatch.</span> Timeline entry{" "}
          <code className="font-mono text-xs">{i.first_mismatch}</code> does not match what the audit log committed to:
          the timeline was altered outside the application. Verify the audit chain and investigate.
        </p>
      )}
    </Panel>
  );
}

function Trigger({ incident }: { incident: IncidentDetail }) {
  const e = incident.trigger_event;
  if (!e) return null;
  const rows = [
    ["Rule", e.rule_id],
    ["Request", e.method && e.endpoint ? `${e.method} ${e.endpoint}` : null],
    ["Response", e.status_code !== null ? String(e.status_code) : null],
    ["Source IP", e.source_ip],
    ["Account", e.actor_label],
    ["User agent", e.user_agent],
  ].filter((r): r is [string, string] => r[1] !== null);
  return (
    <Panel title="What opened it">
      <p className="text-sm">{e.title}</p>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-ink-muted">{k}</dt>
            <dd className="break-all font-mono text-xs leading-5">{v}</dd>
          </div>
        ))}
      </dl>
    </Panel>
  );
}
