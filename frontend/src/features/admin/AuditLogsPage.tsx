import { useEffect, useState, type FormEvent } from "react";
import { useCurrentUser } from "../../app/auth-context";
import { Button, FormError, Notice } from "../../components/forms";
import { listAuditEntries, verifyAuditChain, type AuditFilters } from "../../lib/api/admin";
import type { ApiError } from "../../lib/api/client";
import { AUDIT_RESULTS, type AuditEntry, type AuditResult, type ChainStatus, type Role } from "../../lib/types";
import { asApiError } from "../auth/LoginPage";

const AUDITORS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER"];
const KNOWN_ACTIONS = [
  "auth.login",
  "auth.login_mfa",
  "auth.logout",
  "auth.account_locked",
  "auth.refresh_token_reuse",
  "auth.mfa_enrolled",
  "auth.password_changed",
  "auth.password_reset_requested",
  "auth.password_reset",
  "authz.denied",
  "ratelimit.exceeded",
  "user.created",
  "user.updated",
  "user.mfa_reset",
  "user.deleted",
  "audit.verified",
] as const;

const RESULT_STYLE: Record<AuditEntry["result"], string> = {
  success: "text-ok",
  failure: "text-prov-sim",
  denied: "text-fail",
};

export function AuditLogsPage() {
  const user = useCurrentUser();
  if (!AUDITORS.includes(user.role)) {
    return (
      <div className="max-w-prose space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">Audit logs</h1>
        <p className="text-ink-muted">Audit logs are available to administrators and security engineers.</p>
      </div>
    );
  }
  return <AuditLogViewer />;
}

function AuditLogViewer() {
  const [filters, setFilters] = useState<AuditFilters>({});
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [nextBefore, setNextBefore] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [chain, setChain] = useState<ChainStatus | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  // First page: reloaded whenever the filters change; a stale response is discarded.
  useEffect(() => {
    const controller = new AbortController();
    listAuditEntries(filters, controller.signal)
      .then((page) => {
        setEntries(page.items);
        setNextBefore(page.next_before_seq);
        setError(null);
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(asApiError(err));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [filters]);

  async function loadOlder(before: number) {
    setLoading(true);
    setError(null);
    try {
      const page = await listAuditEntries({ ...filters, before_seq: before });
      setEntries((current) => [...current, ...page.items]);
      setNextBefore(page.next_before_seq);
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setLoading(false);
    }
  }

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const next: AuditFilters = {};
    const action = String(form.get("action"));
    const actor = String(form.get("actor")).trim();
    const result = String(form.get("result"));
    if (action) next.action = action;
    if (actor) next.actor = actor;
    if (result) next.result = result as AuditResult;
    setLoading(true);
    setFilters(next);
  }

  async function verify() {
    setError(null);
    try {
      setChain(await verifyAuditChain());
    } catch (err) {
      setError(asApiError(err));
    }
  }

  return (
    <div className="max-w-6xl space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Audit logs</h1>
          <p className="mt-1 max-w-prose text-ink-muted">
            Every sign-in, permission denial and administrative change, newest first. Each record is chained to the one
            before it, so any edit to history is detectable.
          </p>
        </div>
        <Button variant="secondary" onClick={() => void verify()}>
          Verify integrity
        </Button>
      </header>

      {chain &&
        (chain.intact ? (
          <Notice>
            Chain intact across {chain.records_checked} records. Head hash{" "}
            <code className="break-all font-mono text-xs">{chain.head_hash}</code>
          </Notice>
        ) : (
          <div role="alert" className="rounded border border-fail/60 bg-fail/10 px-3 py-2 text-sm">
            Integrity check failed at record {chain.first_break_seq}: {chain.problem}. Treat this as a security incident.
          </div>
        ))}

      <form onSubmit={applyFilters} className="flex flex-wrap items-end gap-3" aria-label="Filter audit records">
        <label className="space-y-1 text-sm">
          <span className="block font-medium">Action</span>
          <select name="action" defaultValue="" className="rounded border border-line bg-canvas px-2 py-2">
            <option value="">Any action</option>
            {KNOWN_ACTIONS.map((a) => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
        </label>
        <label className="space-y-1 text-sm">
          <span className="block font-medium">Actor email</span>
          <input name="actor" type="text" maxLength={254} className="rounded border border-line bg-canvas px-2 py-2" />
        </label>
        <label className="space-y-1 text-sm">
          <span className="block font-medium">Result</span>
          <select name="result" defaultValue="" className="rounded border border-line bg-canvas px-2 py-2">
            <option value="">Any result</option>
            {AUDIT_RESULTS.map((r) => (
              <option key={r} value={r}>{r}</option>
            ))}
          </select>
        </label>
        <Button type="submit" variant="secondary">Apply</Button>
      </form>

      <FormError error={error} />

      <div className="overflow-x-auto rounded-md border border-line">
        <table className="w-full min-w-[820px] text-left text-sm">
          <caption className="sr-only">Audit records</caption>
          <thead className="bg-raised text-ink-muted">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">#</th>
              <th scope="col" className="px-3 py-2 font-medium">Time (UTC)</th>
              <th scope="col" className="px-3 py-2 font-medium">Actor</th>
              <th scope="col" className="px-3 py-2 font-medium">Action</th>
              <th scope="col" className="px-3 py-2 font-medium">Result</th>
              <th scope="col" className="px-3 py-2 font-medium">Source</th>
              <th scope="col" className="px-3 py-2 font-medium"><span className="sr-only">Details</span></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {entries.map((e) => (
              <AuditRow
                key={e.seq}
                entry={e}
                open={expanded === e.seq}
                onToggle={() => setExpanded(expanded === e.seq ? null : e.seq)}
              />
            ))}
          </tbody>
        </table>
        {!loading && entries.length === 0 && <p className="px-3 py-4 text-sm text-ink-muted">No records match these filters.</p>}
      </div>

      {nextBefore !== null && (
        <Button variant="secondary" busy={loading} onClick={() => void loadOlder(nextBefore)}>
          Load older records
        </Button>
      )}
    </div>
  );
}

function AuditRow({ entry, open, onToggle }: { entry: AuditEntry; open: boolean; onToggle: () => void }) {
  return (
    <>
      <tr className="align-top">
        <td className="px-3 py-2 tabular-nums text-ink-muted">{entry.seq}</td>
        <td className="whitespace-nowrap px-3 py-2 tabular-nums">{entry.occurred_at.replace("T", " ").slice(0, 19)}</td>
        <td className="px-3 py-2">{entry.actor_label}</td>
        <td className="px-3 py-2 font-mono text-xs">{entry.action}</td>
        <td className={`px-3 py-2 ${RESULT_STYLE[entry.result]}`}>{entry.result}</td>
        <td className="px-3 py-2 tabular-nums text-ink-muted">{entry.source_ip ?? "—"}</td>
        <td className="px-3 py-2 text-right">
          <button type="button" className="text-accent underline-offset-2 hover:underline" aria-expanded={open} onClick={onToggle}>
            {open ? "Hide" : "Details"}
          </button>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={7} className="bg-canvas px-3 py-3">
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
              <dt className="text-ink-muted">Resource</dt>
              <dd>{entry.resource_type ? `${entry.resource_type} ${entry.resource_id ?? ""}` : "—"}</dd>
              <dt className="text-ink-muted">Correlation ID</dt>
              <dd className="font-mono">{entry.correlation_id ?? "—"}</dd>
              <dt className="text-ink-muted">Details</dt>
              {/* Rendered as text: audit details may contain attacker-supplied values. */}
              <dd><pre className="whitespace-pre-wrap break-all font-mono">{JSON.stringify(entry.details, null, 2)}</pre></dd>
              <dt className="text-ink-muted">Record hash</dt>
              <dd className="break-all font-mono">{entry.record_hash}</dd>
              <dt className="text-ink-muted">Previous hash</dt>
              <dd className="break-all font-mono">{entry.prev_hash}</dd>
            </dl>
          </td>
        </tr>
      )}
    </>
  );
}
