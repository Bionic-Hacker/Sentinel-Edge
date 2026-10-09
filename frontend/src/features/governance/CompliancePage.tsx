import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useCurrentUser } from "../../app/auth-context";
import { Button, FormError } from "../../components/forms";
import { StatTile, formatTime } from "../../components/secops";
import type { ApiError } from "../../lib/api/client";
import {
  getPosture,
  listChanges,
  listControls,
  listExceptions,
  listRequirements,
  requestException,
  submitChange,
  takeSnapshot,
} from "../../lib/api/governance";
import {
  CHANGE_TYPES,
  EXCEPTION_SCOPES,
  RISK_LEVELS,
  WAF_MODES,
  type ChangeList,
  type ChangeType,
  type ControlList,
  type ExceptionList,
  type ExceptionScope,
  type Posture,
  type Requirement,
  type RiskLevel,
  type WafMode,
} from "../../lib/types";
import { asApiError } from "../auth/LoginPage";
import {
  ChangeStatusBadge,
  ControlStatusBadge,
  ExceptionStatusBadge,
  LEADS,
  REQUESTERS,
  RiskBadge,
  ThreatStatusBadge,
  TrendLine,
  selectBox,
  textArea,
} from "./governance";

const TABS = [
  ["posture", "Posture"],
  ["controls", "Controls"],
  ["requirements", "Requirements"],
  ["exceptions", "Exceptions"],
  ["changes", "Change requests"],
] as const;
type Tab = (typeof TABS)[number][0];

/** Loads once per mount; the result is null while loading. */
function useLoad<T>(load: (signal: AbortSignal) => Promise<T>, reload = 0) {
  const [result, setResult] = useState<{ key: number; data: T | null; error: ApiError | null } | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal)
      .then((data) => setResult({ key: reload, data, error: null }))
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setResult({ key: reload, data: null, error: asApiError(err) });
      });
    return () => controller.abort();
  }, [load, reload]);
  return result;
}

export function CompliancePage() {
  const [params, setParams] = useSearchParams();
  const tab: Tab = (TABS.find(([key]) => key === params.get("tab"))?.[0] ?? "posture") as Tab;
  return (
    <div className="max-w-7xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Compliance</h1>
        <p className="mt-1 max-w-prose text-ink-muted">
          The control catalogue and the requirement, threat, control and evidence matrix; an explainable posture score;
          security exceptions and change requests, where whoever asks can never approve.
        </p>
      </header>
      <nav aria-label="Compliance sections" className="flex flex-wrap gap-1 border-b border-line">
        {TABS.map(([key, label]) => (
          <button
            key={key}
            type="button"
            aria-current={tab === key ? "page" : undefined}
            onClick={() => setParams({ tab: key })}
            className={`-mb-px border-b-2 px-3 py-2 text-sm ${tab === key ? "border-accent font-medium text-ink" : "border-transparent text-ink-muted hover:text-ink"}`}
          >
            {label}
          </button>
        ))}
      </nav>
      {tab === "posture" && <PostureTab />}
      {tab === "controls" && <ControlsTab families={(params.get("families") ?? "").split(",").filter(Boolean)} />}
      {tab === "requirements" && <RequirementsTab />}
      {tab === "exceptions" && <ExceptionsTab />}
      {tab === "changes" && <ChangesTab />}
    </div>
  );
}

// --- Posture --------------------------------------------------------------------------------------

const loadPosture = (signal: AbortSignal) => getPosture(signal);

function PostureTab() {
  const user = useCurrentUser();
  const [snapped, setSnapped] = useState<Posture | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const result = useLoad(loadPosture);
  if (result?.error) return <FormError error={result.error} />;
  const posture = snapped ?? result?.data;
  if (!posture) return <p className="text-sm text-ink-muted">Calculating the posture score…</p>;

  async function snapshot() {
    setBusy(true);
    setError(null);
    try {
      setSnapped(await takeSnapshot());
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  const tone = (score: number) => (score >= 80 ? "ok" : score >= 50 ? "warn" : "fail");
  return (
    <section aria-labelledby="posture-heading" className="space-y-5">
      <h2 id="posture-heading" className="sr-only">
        Posture
      </h2>
      <div className="flex flex-wrap items-end gap-6">
        <dl className="grid grid-cols-2 gap-3">
          <StatTile label="Overall posture" value={posture.overall} note="Every category, planned ones at 0" tone={tone(posture.overall)} />
          <StatTile label="What is built" value={posture.built_scope} note="Measured categories only" tone={tone(posture.built_scope)} />
        </dl>
        <div className="space-y-1">
          <p className="text-xs text-ink-muted">Overall, last {posture.trend.length} snapshots</p>
          <TrendLine label="Overall posture" points={posture.trend.map((p) => ({ taken_at: p.taken_at, value: p.overall }))} />
        </div>
        {LEADS.includes(user.role) && (
          <div>
            <Button variant="secondary" busy={busy} onClick={() => void snapshot()}>
              Record a snapshot now
            </Button>
            <FormError error={error} />
          </div>
        )}
      </div>
      <ul className="space-y-2">
        {posture.categories.map((c) => (
          <li key={c.key} className="rounded-md border border-line bg-surface">
            <details>
              <summary className="flex cursor-pointer flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3 sm:flex-nowrap">
                <span className="min-w-0 flex-1 text-sm font-medium sm:w-56 sm:flex-none">{c.label}</span>
                <svg className="order-last h-2 w-full sm:order-none sm:w-auto sm:flex-1" aria-hidden="true">
                  <rect x={0} y={0} width="100%" height="100%" rx={4} className="fill-raised" />
                  <rect x={0} y={0} width={`${Math.max(c.score, 1)}%`} height="100%" rx={4} className={c.state === "planned" ? "fill-line" : "fill-accent"} />
                </svg>
                <span className="shrink-0 text-right text-sm tabular-nums sm:w-24">
                  {c.state === "planned" ? <span className="text-ink-muted">Planned</span> : `${c.score} / 100`}
                </span>
              </summary>
              <ul className="space-y-1 border-t border-line px-4 py-3 text-sm">
                {c.factors.map((f) => (
                  <li key={f.label} className="flex flex-wrap items-baseline gap-x-3">
                    <span className={`w-14 shrink-0 text-right tabular-nums ${f.points < 0 ? "text-fail" : "text-ink"}`}>
                      {f.points}
                    </span>
                    <span>
                      {f.link ? (
                        <Link to={f.link} className="text-accent hover:underline">
                          {f.label}
                        </Link>
                      ) : (
                        f.label
                      )}
                    </span>
                    {f.refs.length > 0 && (
                      <span className="basis-full text-xs text-ink-muted sm:pl-[4.25rem]">
                        {f.kind === "coverage" ? "Still planned: " : ""}
                        {f.refs.join(", ")}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            </details>
          </li>
        ))}
      </ul>
      <details className="rounded-md border border-line px-4 py-3 text-sm">
        <summary className="cursor-pointer font-medium">How the score is calculated</summary>
        <p className="mt-2 whitespace-pre-wrap text-ink-muted">{posture.method}</p>
      </details>
    </section>
  );
}

// --- Controls -------------------------------------------------------------------------------------

const loadControls = (signal: AbortSignal) => listControls({}, signal);

function ControlsTab({ families }: { families: string[] }) {
  const result = useLoad(loadControls);
  const [status, setStatus] = useState<"" | "implemented" | "planned">("");
  const [q, setQ] = useState("");
  if (result?.error) return <FormError error={result.error} />;
  const data: ControlList | null | undefined = result?.data;
  if (!data) return <p className="text-sm text-ink-muted">Loading the control catalogue…</p>;
  const needle = q.trim().toLowerCase();
  const rows = data.items.filter(
    (c) =>
      (!families.length || families.includes(c.family)) &&
      (!status || c.status === status) &&
      (!needle || `${c.ref} ${c.title} ${c.implementation}`.toLowerCase().includes(needle)),
  );
  return (
    <section aria-labelledby="controls-heading" className="space-y-4">
      <h2 id="controls-heading" className="sr-only">
        Controls
      </h2>
      <dl className="grid grid-cols-3 gap-3 sm:max-w-xl">
        <StatTile label="Implemented" value={data.counts.implemented} tone="ok" />
        <StatTile label="Planned" value={data.counts.planned} />
        <StatTile label="With runnable evidence" value={data.counts.with_evidence} />
      </dl>
      <div className="flex flex-wrap items-end gap-3">
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Status</span>
          <select value={status} onChange={(e) => setStatus(e.target.value as typeof status)} className={selectBox}>
            <option value="">All</option>
            <option value="implemented">Implemented</option>
            <option value="planned">Planned</option>
          </select>
        </label>
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Search</span>
          <input type="search" value={q} onChange={(e) => setQ(e.target.value)} maxLength={100} placeholder="ID, control or file" className="w-56 rounded border border-line bg-canvas px-2 py-1.5 text-sm" />
        </label>
        {families.length > 0 && (
          <p className="pb-1.5 text-sm text-ink-muted">
            Families {families.join(", ")} ·{" "}
            <Link to="/compliance?tab=controls" className="text-accent hover:underline">
              show all
            </Link>
          </p>
        )}
      </div>
      <p className="text-xs text-ink-muted">
        Loaded from <code className="font-mono">docs/security-controls.md</code>, catalogue {data.catalogue_digest.slice(0, 12)}. Every
        cited test and command is checked to exist in CI.
      </p>
      <div className="overflow-x-auto rounded-md border border-line">
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Control catalogue</caption>
          <thead className="bg-surface text-xs text-ink-muted">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">Control</th>
              <th scope="col" className="px-3 py-2 font-medium">Status</th>
              <th scope="col" className="px-3 py-2 font-medium">Evidence</th>
              <th scope="col" className="px-3 py-2 font-medium">Mitigates</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {rows.map((c) => (
              <tr key={c.ref}>
                <td className="max-w-md px-3 py-2">
                  <span className="font-mono text-xs text-ink-muted">{c.ref}</span> <span className="break-words">{c.title}</span>
                  {c.implementation && <span className="mt-0.5 block break-words text-xs text-ink-muted">{c.implementation}</span>}
                  {c.extensions.map((x) => (
                    <span key={`${x.phase}-${x.title}`} className="mt-0.5 block break-words text-xs text-ink-muted">
                      Phase {x.phase}: {x.title}
                    </span>
                  ))}
                </td>
                <td className="whitespace-nowrap px-3 py-2">
                  <ControlStatusBadge status={c.status} />
                  <span className="block text-xs text-ink-muted">Phase {c.phase}</span>
                </td>
                <td className="max-w-xs px-3 py-2 text-xs">
                  {[...c.evidence, ...c.extensions.flatMap((x) => x.evidence)].map((e) => (
                    <span key={`${e.kind}-${e.ref}`} className="block break-all font-mono">
                      {e.ref}
                    </span>
                  ))}
                  {!c.evidence.length && c.evidence_text && <span className="break-words text-ink-muted">{c.evidence_text}</span>}
                </td>
                <td className="px-3 py-2 font-mono text-xs text-ink-muted">{c.threats.join(", ") || "-"}</td>
              </tr>
            ))}
            {!rows.length && (
              <tr>
                <td colSpan={4} className="px-3 py-6 text-center text-ink-muted">
                  No controls match.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

// --- Requirements ---------------------------------------------------------------------------------

const loadRequirements = (signal: AbortSignal) => listRequirements(signal);

function RequirementsTab() {
  const result = useLoad(loadRequirements);
  if (result?.error) return <FormError error={result.error} />;
  const items: Requirement[] | undefined = result?.data?.items;
  if (!items) return <p className="text-sm text-ink-muted">Loading the matrix…</p>;
  return (
    <div className="overflow-x-auto rounded-md border border-line">
      <table className="w-full text-left text-sm">
        <caption className="sr-only">Requirement, threat, control and evidence matrix</caption>
        <thead className="bg-surface text-xs text-ink-muted">
          <tr>
            <th scope="col" className="px-3 py-2 font-medium">Requirement</th>
            <th scope="col" className="px-3 py-2 font-medium">Threats</th>
            <th scope="col" className="px-3 py-2 font-medium">Controls</th>
            <th scope="col" className="px-3 py-2 font-medium">Evidence</th>
            <th scope="col" className="px-3 py-2 font-medium">Phase</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {items.map((r) => (
            <tr key={r.ref}>
              <td className="px-3 py-2">
                <span className="font-mono text-xs text-ink-muted">{r.ref}</span> {r.title}
                <span className="mt-0.5 block max-w-sm break-words text-xs text-ink-muted">{r.control_text}</span>
              </td>
              <td className="px-3 py-2 text-xs">
                {r.threats.map((t) => (
                  <span key={t.ref} className="mb-1 flex items-center gap-2">
                    <span className="font-mono">{t.ref}</span>
                    <ThreatStatusBadge status={t.status} />
                  </span>
                ))}
              </td>
              <td className="px-3 py-2 font-mono text-xs text-ink-muted">{r.controls.join(", ")}</td>
              <td className="max-w-xs break-words px-3 py-2 text-xs text-ink-muted">{r.evidence_text}</td>
              <td className="whitespace-nowrap px-3 py-2 text-xs">{r.phase_text}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// --- Exceptions -----------------------------------------------------------------------------------

const loadExceptions = (signal: AbortSignal) => listExceptions(signal);

function ExceptionsTab() {
  const user = useCurrentUser();
  const [reload, setReload] = useState(0);
  const result = useLoad(loadExceptions, reload);
  const data: ExceptionList | null | undefined = result?.data;
  return (
    <section aria-labelledby="exceptions-heading" className="space-y-4">
      <h2 id="exceptions-heading" className="sr-only">
        Exceptions
      </h2>
      {result?.error && <FormError error={result.error} />}
      {!data && !result?.error && <p className="text-sm text-ink-muted">Loading exceptions…</p>}
      {data && (
        <>
          <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <StatTile label="Awaiting a decision" value={data.counts.requested ?? 0} {...(data.counts.requested ? { tone: "warn" as const } : {})} />
            <StatTile label="In force" value={data.counts.approved ?? 0} />
            <StatTile label="Expiring in 30 days" value={data.counts.expiring_30d ?? 0} {...(data.counts.expiring_30d ? { tone: "warn" as const } : {})} />
            <StatTile label="Expired" value={data.counts.expired ?? 0} />
          </dl>
          <div className="overflow-x-auto rounded-md border border-line">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Security exceptions, newest first</caption>
              <thead className="bg-surface text-xs text-ink-muted">
                <tr>
                  <th scope="col" className="px-3 py-2 font-medium">Exception</th>
                  <th scope="col" className="px-3 py-2 font-medium">Risk</th>
                  <th scope="col" className="px-3 py-2 font-medium">Status</th>
                  <th scope="col" className="px-3 py-2 font-medium">Requested by</th>
                  <th scope="col" className="px-3 py-2 font-medium">Approved by</th>
                  <th scope="col" className="px-3 py-2 font-medium">Expires</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {data.items.map((e) => (
                  <tr key={e.id}>
                    <td className="max-w-md px-3 py-2">
                      <Link to={`/compliance/exceptions/${e.id}`} className="break-words text-accent hover:underline">
                        {e.reference}: {e.title}
                      </Link>
                      <span className="block break-words text-xs text-ink-muted">
                        {e.application.name} · {e.scope.replace("_", " ")} · {e.scope_ref}
                        {e.imported && " · imported"}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <RiskBadge level={e.risk_level} />
                    </td>
                    <td className="px-3 py-2">
                      <ExceptionStatusBadge status={e.status} />
                    </td>
                    <td className="px-3 py-2 text-xs">{e.requester_label}</td>
                    <td className="px-3 py-2 text-xs">{e.approver_label ?? "-"}</td>
                    <td className="whitespace-nowrap px-3 py-2 text-xs tabular-nums">
                      {e.expires_on}
                      {e.days_left !== null && (
                        <span className={`block ${e.days_left <= 30 ? "text-prov-sim" : "text-ink-muted"}`}>{e.days_left} days left</span>
                      )}
                    </td>
                  </tr>
                ))}
                {!data.items.length && (
                  <tr>
                    <td colSpan={6} className="px-3 py-6 text-center text-ink-muted">
                      No exceptions.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
      {REQUESTERS.includes(user.role) && <RequestException onDone={() => setReload((n) => n + 1)} />}
    </section>
  );
}

function Labelled({ label, children, wide = false }: { label: string; children: ReactNode; wide?: boolean }) {
  return (
    <label className={`space-y-1 text-sm ${wide ? "sm:col-span-2" : ""}`}>
      <span className="block text-ink-muted">{label}</span>
      {children}
    </label>
  );
}

function RequestException({ onDone }: { onDone: () => void }) {
  const [scope, setScope] = useState<ExceptionScope>("dependency");
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const f = new FormData(formEl);
    const text = (name: string) => String(f.get(name) ?? "").trim();
    const gate: Record<string, string> = {};
    if (scope === "scan_finding") {
      if (text("fingerprint")) gate.fingerprint = text("fingerprint");
      else {
        gate.tool = text("tool");
        gate.rule = text("rule");
        if (text("component")) gate.component = text("component");
      }
    }
    setBusy(true);
    setError(null);
    try {
      const created = await requestException({
        title: text("title"),
        scope,
        scope_ref: text("scope_ref"),
        ...(scope === "scan_finding" ? { gate_match: gate } : {}),
        risk_level: text("risk_level") as RiskLevel,
        risk: text("risk"),
        justification: text("justification"),
        compensating_control: text("compensating_control"),
        control_refs: text("control_refs").split(",").map((s) => s.trim().toUpperCase()).filter(Boolean),
        implementation: text("implementation"),
        exit_criteria: text("exit_criteria"),
        expires_on: text("expires_on"),
      });
      formEl.reset();
      setDone(created.reference);
      onDone();
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="request-exception" className="rounded-md border border-line bg-surface p-5">
      <h3 id="request-exception" className="mb-1 text-base font-semibold">
        Request an exception
      </h3>
      <p className="mb-3 text-xs text-ink-muted">
        A different lead must approve it. Expiry limits: critical 30 days, high 90, medium 180, low 365.
      </p>
      <form onSubmit={(e) => void submit(e)} className="grid gap-3 sm:grid-cols-2">
        <Labelled label="Title" wide>
          <input name="title" required minLength={5} maxLength={200} className={textArea} />
        </Labelled>
        <Labelled label="Scope">
          <select value={scope} onChange={(e) => setScope(e.target.value as ExceptionScope)} className={`${selectBox} w-full`}>
            {EXCEPTION_SCOPES.map((s) => (
              <option key={s} value={s}>
                {s.replace("_", " ")}
              </option>
            ))}
          </select>
        </Labelled>
        <Labelled label="What it covers">
          <input name="scope_ref" required maxLength={200} className={textArea} />
        </Labelled>
        {scope === "scan_finding" && (
          <>
            <Labelled label="Finding fingerprint (or tool and rule below)">
              <input name="fingerprint" maxLength={64} className={textArea} />
            </Labelled>
            <Labelled label="Tool">
              <input name="tool" maxLength={16} placeholder="trivy" className={textArea} />
            </Labelled>
            <Labelled label="Rule">
              <input name="rule" maxLength={200} placeholder="CVE-2026-0001" className={textArea} />
            </Labelled>
            <Labelled label="Component pattern (optional)">
              <input name="component" maxLength={200} placeholder="curl@*" className={textArea} />
            </Labelled>
          </>
        )}
        <Labelled label="Risk level">
          <select name="risk_level" defaultValue="low" className={`${selectBox} w-full capitalize`}>
            {RISK_LEVELS.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </Labelled>
        <Labelled label="Expires on">
          <input name="expires_on" type="date" required className={textArea} />
        </Labelled>
        <Labelled label="Risk" wide>
          <textarea name="risk" required minLength={20} rows={2} maxLength={4000} className={textArea} />
        </Labelled>
        <Labelled label="Business justification" wide>
          <textarea name="justification" required minLength={20} rows={2} maxLength={4000} className={textArea} />
        </Labelled>
        <Labelled label="Compensating control" wide>
          <textarea name="compensating_control" required minLength={20} rows={2} maxLength={4000} className={textArea} />
        </Labelled>
        <Labelled label="Catalogue controls (optional)">
          <input name="control_refs" placeholder="C-CICD-02" maxLength={300} className={textArea} />
        </Labelled>
        <Labelled label="Exit criteria (optional)">
          <input name="exit_criteria" maxLength={4000} className={textArea} />
        </Labelled>
        <Labelled label="Implementation (optional)" wide>
          <input name="implementation" maxLength={4000} className={textArea} />
        </Labelled>
        <div className="sm:col-span-2">
          <FormError error={error} />
          {done && <p role="status" className="text-sm text-ok">Requested {done}.</p>}
          <Button type="submit" busy={busy} className="mt-2">
            Request exception
          </Button>
        </div>
      </form>
    </section>
  );
}

// --- Change requests --------------------------------------------------------------------------------

const loadChanges = (signal: AbortSignal) => listChanges(signal);

function ChangesTab() {
  const user = useCurrentUser();
  const [reload, setReload] = useState(0);
  const result = useLoad(loadChanges, reload);
  const data: ChangeList | null | undefined = result?.data;
  return (
    <section aria-labelledby="changes-heading" className="space-y-4">
      <h2 id="changes-heading" className="sr-only">
        Change requests
      </h2>
      {result?.error && <FormError error={result.error} />}
      {!data && !result?.error && <p className="text-sm text-ink-muted">Loading change requests…</p>}
      {data && (
        <div className="overflow-x-auto rounded-md border border-line">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Change requests, newest first</caption>
            <thead className="bg-surface text-xs text-ink-muted">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">Change</th>
                <th scope="col" className="px-3 py-2 font-medium">Risk</th>
                <th scope="col" className="px-3 py-2 font-medium">Status</th>
                <th scope="col" className="px-3 py-2 font-medium">Requested by</th>
                <th scope="col" className="px-3 py-2 font-medium">Approved by</th>
                <th scope="col" className="px-3 py-2 font-medium">Updated</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {data.items.map((c) => (
                <tr key={c.id}>
                  <td className="max-w-md px-3 py-2">
                    <Link to={`/compliance/changes/${c.id}`} className="break-words text-accent hover:underline">
                      {c.reference}: {c.title}
                    </Link>
                    <span className="block text-xs text-ink-muted">
                      {c.application.name} · {c.change_type.replace("_", " ")}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <RiskBadge level={c.risk_level} />
                  </td>
                  <td className="px-3 py-2">
                    <ChangeStatusBadge status={c.status} />
                  </td>
                  <td className="px-3 py-2 text-xs">{c.requester_label}</td>
                  <td className="px-3 py-2 text-xs">{c.approver_label ?? "-"}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs tabular-nums text-ink-muted">{formatTime(c.updated_at)}</td>
                </tr>
              ))}
              {!data.items.length && (
                <tr>
                  <td colSpan={6} className="px-3 py-6 text-center text-ink-muted">
                    No change requests.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
      {REQUESTERS.includes(user.role) && <SubmitChange onDone={() => setReload((n) => n + 1)} />}
    </section>
  );
}

function SubmitChange({ onDone }: { onDone: () => void }) {
  const [type, setType] = useState<ChangeType>("configuration");
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const f = new FormData(formEl);
    const text = (name: string) => String(f.get(name) ?? "").trim();
    setBusy(true);
    setError(null);
    try {
      const created = await submitChange({
        title: text("title"),
        change_type: type,
        description: text("description"),
        risk_level: text("risk_level") as RiskLevel,
        impact: text("impact"),
        rollback_plan: text("rollback_plan"),
        validation_plan: text("validation_plan"),
        ...(type === "waf_rule" ? { target: { rule_id: text("rule_id").toUpperCase(), mode: text("mode") as WafMode } } : {}),
      });
      formEl.reset();
      setDone(created.reference);
      onDone();
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="submit-change" className="rounded-md border border-line bg-surface p-5">
      <h3 id="submit-change" className="mb-1 text-base font-semibold">
        Submit a change request
      </h3>
      <p className="mb-3 text-xs text-ink-muted">
        A different lead approves it. WAF rule changes drive the simulated WAF; real WAF rules change only through
        reviewed Terraform.
      </p>
      <form onSubmit={(e) => void submit(e)} className="grid gap-3 sm:grid-cols-2">
        <Labelled label="Title" wide>
          <input name="title" required minLength={5} maxLength={200} className={textArea} />
        </Labelled>
        <Labelled label="Type">
          <select value={type} onChange={(e) => setType(e.target.value as ChangeType)} className={`${selectBox} w-full`}>
            {CHANGE_TYPES.map((t) => (
              <option key={t} value={t}>
                {t === "waf_rule" ? "WAF rule (simulated)" : t}
              </option>
            ))}
          </select>
        </Labelled>
        <Labelled label="Risk level">
          <select name="risk_level" defaultValue="medium" className={`${selectBox} w-full capitalize`}>
            {RISK_LEVELS.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </Labelled>
        {type === "waf_rule" && (
          <>
            <Labelled label="WAF rule">
              <input name="rule_id" required placeholder="SQLI-001" maxLength={12} className={textArea} />
            </Labelled>
            <Labelled label="New mode">
              <select name="mode" className={`${selectBox} w-full`}>
                {WAF_MODES.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </Labelled>
          </>
        )}
        {(
          [
            ["description", "What changes and why"],
            ["impact", "Impact"],
            ["rollback_plan", "Rollback plan"],
            ["validation_plan", "Validation plan"],
          ] as const
        ).map(([name, label]) => (
          <Labelled key={name} label={label} wide>
            <textarea name={name} required minLength={20} rows={2} maxLength={4000} className={textArea} />
          </Labelled>
        ))}
        <div className="sm:col-span-2">
          <FormError error={error} />
          {done && <p role="status" className="text-sm text-ok">Submitted {done}.</p>}
          <Button type="submit" busy={busy} className="mt-2">
            Submit change request
          </Button>
        </div>
      </form>
    </section>
  );
}
