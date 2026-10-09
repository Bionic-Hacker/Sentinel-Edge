import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useCurrentUser } from "../../app/auth-context";
import { Button, FormError } from "../../components/forms";
import { formatTime } from "../../components/secops";
import type { ApiError } from "../../lib/api/client";
import { createThreatModel, listThreatModels } from "../../lib/api/governance";
import { listApplications } from "../../lib/api/secops";
import { MODEL_METHODS, type Application, type ModelMethod, type ThreatModelSummary } from "../../lib/types";
import { asApiError } from "../auth/LoginPage";
import { LEADS, selectBox, textArea } from "./governance";

export function ThreatModelingPage() {
  const user = useCurrentUser();
  const [result, setResult] = useState<{ items: ThreatModelSummary[] | null; error: ApiError | null } | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    listThreatModels(controller.signal)
      .then((data) => setResult({ items: data.items, error: null }))
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setResult({ items: null, error: asApiError(err) });
      });
    return () => controller.abort();
  }, []);

  const [showArchived, setShowArchived] = useState(false);
  const all = result?.items ?? [];
  const archived = all.filter((m) => m.status === "archived").length;
  const models = showArchived ? all : all.filter((m) => m.status !== "archived");
  return (
    <div className="max-w-6xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Threat Modeling</h1>
        <p className="mt-1 max-w-prose text-ink-muted">
          Assets, trust boundaries, data flows and threats (STRIDE or PASTA), each threat linked to the controls that mitigate
          it. SentinelEdge's own model is maintained as code and loaded from the reviewed threat model; models for other
          applications are built here.
        </p>
      </header>
      {result?.error && <FormError error={result.error} />}
      {!result && <p className="text-sm text-ink-muted">Loading threat models…</p>}
      {archived > 0 && (
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={showArchived} onChange={(e) => setShowArchived(e.target.checked)} />
          Show archived models ({archived})
        </label>
      )}
      {result?.items && !models.length && <p className="text-sm text-ink-muted">No threat models you can see yet.</p>}
      {models.length > 0 && (
        <div className="overflow-x-auto rounded-md border border-line">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Threat models</caption>
            <thead className="bg-surface text-xs text-ink-muted">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">Model</th>
                <th scope="col" className="px-3 py-2 font-medium">Method</th>
                <th scope="col" className="px-3 py-2 text-right font-medium">Threats</th>
                <th scope="col" className="px-3 py-2 text-right font-medium">Mitigated</th>
                <th scope="col" className="px-3 py-2 text-right font-medium">Highest open risk</th>
                <th scope="col" className="px-3 py-2 font-medium">Updated</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {models.map((m) => (
                <tr key={m.id}>
                  <td className="px-3 py-2">
                    <Link to={`/threat-modeling/${m.id}`} className="text-accent hover:underline">
                      {m.reference}: {m.name}
                    </Link>
                    <span className="block text-xs text-ink-muted">
                      {m.application.name} · {m.origin === "catalogue" ? `maintained as code, v${m.version_label}` : m.status}
                    </span>
                  </td>
                  <td className="px-3 py-2 uppercase text-ink-muted">{m.method}</td>
                  <td className="px-3 py-2 text-right tabular-nums">{m.threat_count}</td>
                  <td className="px-3 py-2 text-right tabular-nums">{m.by_status.mitigated}</td>
                  <td className={`px-3 py-2 text-right tabular-nums ${m.highest_open_risk >= 6 ? "font-medium text-fail" : ""}`}>
                    {m.highest_open_risk || "-"}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs tabular-nums text-ink-muted">{formatTime(m.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {LEADS.includes(user.role) && <NewModel />}
    </div>
  );
}

function NewModel() {
  const navigate = useNavigate();
  const [apps, setApps] = useState<Application[]>([]);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    listApplications(controller.signal)
      .then((items) => setApps(items.filter((a) => a.status === "active")))
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(asApiError(err));
      });
    return () => controller.abort();
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const model = await createThreatModel({
        application_id: String(form.get("application_id")),
        name: String(form.get("name")).trim(),
        method: String(form.get("method")) as ModelMethod,
        scope: String(form.get("scope")).trim(),
      });
      void navigate(`/threat-modeling/${model.id}`);
    } catch (err) {
      setError(asApiError(err));
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="new-model" className="rounded-md border border-line bg-surface p-5">
      <h2 id="new-model" className="mb-3 text-base font-semibold">
        New threat model
      </h2>
      <form onSubmit={(e) => void submit(e)} className="grid gap-3 sm:grid-cols-3">
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Application</span>
          <select name="application_id" required className={`${selectBox} w-full`}>
            {apps.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        </label>
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Name</span>
          <input name="name" required maxLength={200} className={textArea} />
        </label>
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Method</span>
          <select name="method" className={`${selectBox} w-full uppercase`}>
            {MODEL_METHODS.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </label>
        <label className="space-y-1 text-sm sm:col-span-3">
          <span className="block text-ink-muted">Scope</span>
          <textarea name="scope" rows={2} maxLength={4000} className={textArea} />
        </label>
        <div className="sm:col-span-3">
          <FormError error={error} />
          <Button type="submit" busy={busy} disabled={!apps.length} className="mt-2">
            Create model
          </Button>
        </div>
      </form>
    </section>
  );
}
