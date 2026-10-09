import { useEffect, useState, type FormEvent, type MouseEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { Button, FormError } from "../../components/forms";
import { formatTime } from "../../components/secops";
import { ApiError } from "../../lib/api/client";
import { closeException, decideException, getChange, getException, transitionChange } from "../../lib/api/governance";
import type { ChangeDetail, ChangeStatus, ExceptionDetail } from "../../lib/types";
import { asApiError } from "../auth/LoginPage";
import {
  ChangeStatusBadge,
  ExceptionStatusBadge,
  Fact,
  History,
  MOVE_LABEL,
  RiskBadge,
  textArea,
} from "./governance";

interface Loaded<T> {
  id: string;
  data: T | null;
  error: ApiError | null;
}

function useRecord<T>(recordId: string, load: (id: string, signal: AbortSignal) => Promise<T>) {
  const [loaded, setLoaded] = useState<Loaded<T> | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    load(recordId, controller.signal)
      .then((data) => setLoaded({ id: recordId, data, error: null }))
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setLoaded({ id: recordId, data: null, error: asApiError(err) });
      });
    return () => controller.abort();
  }, [recordId, load]);
  const current = loaded?.id === recordId ? loaded : null;
  return [current, (data: T) => setLoaded({ id: recordId, data, error: null })] as const;
}

/** Run `then` with the form a button belongs to. */
function withForm(event: MouseEvent<HTMLButtonElement>, then: (form: HTMLFormElement) => void) {
  const form = event.currentTarget.form;
  if (form) then(form);
}

/** A 409 stale_version: someone else changed the record first. */
const isStale = (err: ApiError | null) => err?.status === 409 && err.code === "stale_version";

function SeparationOfDuties({ what }: { what: string }) {
  return (
    <p role="note" className="rounded-md border border-prov-sim/50 bg-prov-sim/10 px-4 py-3 text-sm">
      You raised this {what}, so another lead must decide it (separation of duties). The server refuses a self-approval, and so
      does the database.
    </p>
  );
}

// --- Exceptions -----------------------------------------------------------------------------------

const loadException = (id: string, signal: AbortSignal) => getException(id, signal);

export function ExceptionDetailPage() {
  const { exceptionId = "" } = useParams();
  const [current, setData] = useRecord(exceptionId, loadException);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);

  const back = (
    <Link to="/compliance?tab=exceptions" className="text-sm text-accent hover:underline">
      ← All exceptions
    </Link>
  );
  if (current?.error) {
    return (
      <div className="max-w-5xl space-y-4">
        {back}
        <FormError error={current.error} />
      </div>
    );
  }
  const e = current?.data;
  if (!e) return <p className="text-ink-muted">Loading the exception…</p>;
  const { id, version } = e;

  async function act(run: () => Promise<ExceptionDetail>) {
    setBusy(true);
    setError(null);
    try {
      setData(await run());
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  function decide(approve: boolean, form: HTMLFormElement) {
    const note = String(new FormData(form).get("note") ?? "").trim();
    void act(() => decideException(id, { approve, note, version }));
  }

  function close(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const note = String(new FormData(event.currentTarget).get("note") ?? "").trim();
    void act(() => closeException(id, { note, version }));
  }

  return (
    <div className="max-w-5xl space-y-6">
      {back}
      <header className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">
          {e.reference}: {e.title}
        </h1>
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <ExceptionStatusBadge status={e.status} />
          <RiskBadge level={e.risk_level} />
          <span className="text-ink-muted">
            {e.application.name} · {e.scope.replace("_", " ")} · expires {e.expires_on}
            {e.days_left !== null && ` (${e.days_left} days left)`}
          </span>
        </div>
        {e.imported && (
          <p className="text-xs text-ink-muted">
            Imported from docs/governance/exceptions.md: approved before separation of duties was enforced in the application.
          </p>
        )}
      </header>
      {e.permissions.separation_of_duties && <SeparationOfDuties what="exception" />}

      <dl className="grid gap-4 sm:grid-cols-2">
        <Fact label="Covers">{e.scope_ref}</Fact>
        {e.gate_match && (
          <Fact label="Scan gate match">
            <code className="font-mono text-xs">
              {Object.entries(e.gate_match)
                .map(([k, v]) => `${k} = ${v}`)
                .join(", ")}
            </code>
          </Fact>
        )}
        <Fact label="Risk">{e.risk}</Fact>
        <Fact label="Business justification">{e.justification}</Fact>
        <Fact label="Compensating control">{e.compensating_control}</Fact>
        <Fact label="Catalogue controls">{e.control_refs.join(", ") || "None named"}</Fact>
        {e.implementation && <Fact label="Implementation">{e.implementation}</Fact>}
        {e.exit_criteria && <Fact label="Exit criteria">{e.exit_criteria}</Fact>}
        <Fact label="Requested by">
          {e.requester_label}, {formatTime(e.created_at)}
        </Fact>
        <Fact label="Decision">
          {e.approver_label ? `${e.status === "rejected" ? "Rejected" : "Approved"} by ${e.approver_label}` : "Not decided yet"}
          {e.decided_at && `, ${formatTime(e.decided_at)}`}
          {e.decision_note && <span className="block text-ink-muted">{e.decision_note}</span>}
        </Fact>
        {e.end_note && <Fact label="Ended">{e.end_note}</Fact>}
        <Fact label="Longest allowed for this risk">{e.max_days} days</Fact>
      </dl>

      <FormError error={error} />
      {isStale(error) && <p className="text-sm text-ink-muted">Reload the page to see the latest version.</p>}

      {e.permissions.can_decide && (
        <form
          onSubmit={(ev) => ev.preventDefault()}
          aria-label="Decide"
          className="space-y-3 rounded-md border border-line bg-surface p-4"
        >
          <label className="block space-y-1 text-sm">
            <span className="block text-ink-muted">Decision note (required to reject)</span>
            <textarea name="note" rows={2} maxLength={4000} className={textArea} />
          </label>
          <div className="flex gap-2">
            <Button type="button" busy={busy} onClick={(ev) => withForm(ev, (form) => decide(true, form))}>
              Approve until {e.expires_on}
            </Button>
            <Button type="button" variant="danger" busy={busy} onClick={(ev) => withForm(ev, (form) => decide(false, form))}>
              Reject
            </Button>
          </div>
        </form>
      )}
      {e.permissions.can_close && (
        <form onSubmit={close} aria-label="Close" className="space-y-3 rounded-md border border-line p-4">
          <label className="block space-y-1 text-sm">
            <span className="block text-ink-muted">
              {e.status === "requested" ? "Why withdraw the request" : "Why end it early (for example, the issue is fixed)"}
            </span>
            <textarea name="note" required minLength={10} rows={2} maxLength={2000} className={textArea} />
          </label>
          <Button type="submit" variant="secondary" busy={busy}>
            {e.status === "requested" ? "Withdraw request" : "Close exception"}
          </Button>
        </form>
      )}
      <History entries={e.history} />
    </div>
  );
}

// --- Change requests ------------------------------------------------------------------------------

const loadChange = (id: string, signal: AbortSignal) => getChange(id, signal);

export function ChangeDetailPage() {
  const { changeId = "" } = useParams();
  const [current, setData] = useRecord(changeId, loadChange);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);

  const back = (
    <Link to="/compliance?tab=changes" className="text-sm text-accent hover:underline">
      ← All change requests
    </Link>
  );
  if (current?.error) {
    return (
      <div className="max-w-5xl space-y-4">
        {back}
        <FormError error={current.error} />
      </div>
    );
  }
  const c: ChangeDetail | null | undefined = current?.data;
  if (!c) return <p className="text-ink-muted">Loading the change request…</p>;
  const { id, version } = c;

  async function move(to: ChangeStatus, form: HTMLFormElement) {
    const f = new FormData(form);
    const note = String(f.get("note") ?? "").trim();
    const ref = String(f.get("implementation_ref") ?? "").trim();
    setBusy(true);
    setError(null);
    try {
      setData(await transitionChange(id, { to, note, version, ...(ref ? { implementation_ref: ref } : {}) }));
      form.reset();
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="max-w-5xl space-y-6">
      {back}
      <header className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">
          {c.reference}: {c.title}
        </h1>
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <ChangeStatusBadge status={c.status} />
          <RiskBadge level={c.risk_level} />
          <span className="text-ink-muted">
            {c.application.name} · {c.change_type === "waf_rule" ? "WAF rule (simulated)" : c.change_type}
          </span>
        </div>
      </header>
      {c.separation_of_duties && <SeparationOfDuties what="change request" />}

      <dl className="grid gap-4 sm:grid-cols-2">
        <Fact label="What changes and why">{c.description}</Fact>
        <Fact label="Impact">{c.impact}</Fact>
        <Fact label="Rollback plan">{c.rollback_plan}</Fact>
        <Fact label="Validation plan">{c.validation_plan}</Fact>
        {c.target && (
          <Fact label="Simulated WAF">
            {c.target.rule_id} to <span className="font-medium">{c.target.mode}</span>
            {c.previous_state && ` (was ${c.previous_state.mode})`}
          </Fact>
        )}
        <Fact label="Requested by">
          {c.requester_label}, {formatTime(c.created_at)}
        </Fact>
        <Fact label="Decision">
          {c.approver_label ? `${c.status === "rejected" ? "Rejected" : "Approved"} by ${c.approver_label}` : "Not decided yet"}
          {c.decided_at && `, ${formatTime(c.decided_at)}`}
          {c.decision_note && <span className="block text-ink-muted">{c.decision_note}</span>}
        </Fact>
        {c.implemented_at && (
          <Fact label="Implemented">
            by {c.implemented_by_label}, {formatTime(c.implemented_at)}
            {c.implementation_ref && <span className="block break-all font-mono text-xs">{c.implementation_ref}</span>}
          </Fact>
        )}
        {c.closing_note && <Fact label="Closing note">{c.closing_note}</Fact>}
      </dl>

      <FormError error={error} />
      {isStale(error) && <p className="text-sm text-ink-muted">Reload the page to see the latest version.</p>}

      {c.available_moves.length > 0 && (
        <form onSubmit={(ev) => ev.preventDefault()} aria-label="Next step" className="space-y-3 rounded-md border border-line bg-surface p-4">
          <label className="block space-y-1 text-sm">
            <span className="block text-ink-muted">Note (required to reject, cancel, validate or roll back)</span>
            <textarea name="note" rows={2} maxLength={4000} className={textArea} />
          </label>
          {c.available_moves.includes("implemented") && c.change_type !== "waf_rule" && (
            <label className="block space-y-1 text-sm">
              <span className="block text-ink-muted">Implemented by (pull request URL or commit)</span>
              <input name="implementation_ref" maxLength={200} className={textArea} />
            </label>
          )}
          <div className="flex flex-wrap gap-2">
            {c.available_moves.map((to) => (
              <Button
                key={to}
                type="button"
                busy={busy}
                variant={to === "rejected" || to === "rolled_back" ? "danger" : to === "cancelled" ? "secondary" : "primary"}
                onClick={(ev) => withForm(ev, (form) => void move(to, form))}
              >
                {MOVE_LABEL[to]}
              </Button>
            ))}
          </div>
        </form>
      )}
      <History entries={c.history} />
    </div>
  );
}
