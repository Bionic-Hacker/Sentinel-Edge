import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { BarList } from "../../components/charts";
import { TrashIcon } from "../../components/ConfirmDialog";
import { Button, FormError } from "../../components/forms";
import { StatTile } from "../../components/secops";
import { ApiError } from "../../lib/api/client";
import {
  addElement,
  addThreat,
  archiveThreatModel,
  deleteThreatModel,
  getThreatModel,
  updateElement,
  updateThreat,
  updateThreatModel,
} from "../../lib/api/governance";
import {
  ELEMENT_KINDS,
  PASTA_STAGES,
  THREAT_STATUSES,
  type ElementKind,
  type PastaStage,
  type Threat,
  type ThreatModelDetail,
  type ThreatStatus,
} from "../../lib/types";
import { asApiError } from "../auth/LoginPage";
import { RiskMatrix, ThreatStatusBadge, selectBox, textArea, threatStatusLabel } from "./governance";
import { RemoveModelDialog } from "./RemoveModelDialog";

const CARRYING: readonly ThreatStatus[] = ["open", "planned", "partly_mitigated"];
const ELEMENT_LABEL: Record<ElementKind, string> = {
  asset: "Assets",
  boundary: "Trust boundaries",
  flow: "Data flows",
  attack_path: "Attack paths",
  residual_risk: "Residual risk",
};
const STAGE_LABEL: Record<PastaStage, string> = {
  objectives: "1. Business and security objectives",
  technical_scope: "2. Technical scope",
  decomposition: "3. Application decomposition",
  threat_analysis: "4. Threat analysis",
  vulnerability_analysis: "5. Weakness and vulnerability analysis",
  attack_modeling: "6. Attack modelling",
  risk_impact: "7. Risk and impact analysis",
};

interface Loaded {
  id: string;
  data: ThreatModelDetail | null;
  error: ApiError | null;
}

export function ThreatModelPage() {
  const { modelId = "" } = useParams();
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [removing, setRemoving] = useState(false);
  const [removeBusy, setRemoveBusy] = useState(false);
  const [removeError, setRemoveError] = useState<ApiError | null>(null);
  const navigate = useNavigate();
  const current = loaded?.id === modelId ? loaded : null;

  useEffect(() => {
    const controller = new AbortController();
    getThreatModel(modelId, controller.signal)
      .then((data) => setLoaded({ id: modelId, data, error: null }))
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setLoaded({ id: modelId, data: null, error: asApiError(err) });
      });
    return () => controller.abort();
  }, [modelId]);

  const back = (
    <Link to="/threat-modeling" className="text-sm text-accent hover:underline">
      ← All threat models
    </Link>
  );
  if (current?.error) {
    return (
      <div className="max-w-6xl space-y-4">
        {back}
        <FormError error={current.error} />
      </div>
    );
  }
  const model = current?.data;
  if (!model) return <p className="text-ink-muted">Loading the threat model…</p>;
  const update = (data: ThreatModelDetail) => setLoaded({ id: modelId, data, error: null });
  const { version } = model;

  async function remove(how: "archive" | "delete") {
    setRemoveBusy(true);
    setRemoveError(null);
    try {
      if (how === "delete") {
        await deleteThreatModel(modelId);
        void navigate("/threat-modeling", { replace: true });
        return;
      }
      update(await archiveThreatModel(modelId, version));
      setRemoving(false);
    } catch (err) {
      setRemoveError(asApiError(err));
      setRemoving(false);
    } finally {
      setRemoveBusy(false);
    }
  }
  const live = model.threats.filter((t) => !t.retired);
  const carrying = live.filter((t) => CARRYING.includes(t.status));

  return (
    <div className="max-w-7xl space-y-6">
      {back}
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">
          {model.reference}: {model.name}
        </h1>
        <p className="mt-1 text-ink-muted">
          {model.application.name} · <span className="uppercase">{model.method}</span> · version {model.version_label} ·{" "}
          {model.status}
        </p>
        {model.scope && <p className="mt-2 max-w-prose whitespace-pre-wrap break-words text-sm">{model.scope}</p>}
        {(model.permissions.can_archive || model.permissions.can_delete) && (
          <Button variant="danger" className="mt-3 gap-2" onClick={() => setRemoving(true)}>
            <TrashIcon />
            Delete
          </Button>
        )}
        <FormError error={removeError} />
      </header>
      {removing && (
        <RemoveModelDialog
          reference={model.reference}
          name={model.name}
          canArchive={model.permissions.can_archive}
          canDelete={model.permissions.can_delete}
          busy={removeBusy}
          onArchive={() => void remove("archive")}
          onDelete={() => void remove("delete")}
          onCancel={() => setRemoving(false)}
        />
      )}
      {model.status === "archived" && (
        <p className="rounded-md border border-line bg-surface px-4 py-3 text-sm text-ink-muted">
          Archived: kept with its history, marked out of use.
        </p>
      )}
      {model.permissions.maintained_as_code && (
        <p className="rounded-md border border-line bg-surface px-4 py-3 text-sm text-ink-muted">
          Maintained as code: this model is loaded from <code className="font-mono text-ink">docs/threat-model.md</code> and
          changes only through a reviewed pull request, so it is read-only here.
        </p>
      )}

      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        <StatTile label="Threats" value={live.length} />
        <StatTile label="Mitigated" value={model.stats.by_status.mitigated} tone="ok" />
        <StatTile label="Carrying risk" value={carrying.length} note="Open, planned or partly mitigated" {...(carrying.length ? { tone: "warn" as const } : {})} />
        <StatTile label="No control" value={model.stats.unmapped.length} {...(model.stats.unmapped.length ? { tone: "fail" as const } : { tone: "ok" as const })} />
        <StatTile label="Only planned controls" value={model.stats.only_planned_controls.length} />
      </dl>

      <div className="grid gap-6 md:grid-cols-2">
        <section aria-labelledby="matrix-heading" className="space-y-2">
          <h2 id="matrix-heading" className="text-base font-semibold">
            Risk still carried
          </h2>
          <RiskMatrix cells={model.stats.matrix} />
        </section>
        <section aria-labelledby="stride-heading" className="space-y-2">
          <h2 id="stride-heading" className="text-base font-semibold">
            Threats by category
          </h2>
          <BarList
            label="Threats by STRIDE category"
            empty="No threats yet."
            items={Object.entries(model.stats.by_stride).map(([key, value]) => ({ key, label: STRIDE_NAME[key] ?? key, value }))}
          />
        </section>
      </div>

      {model.method === "pasta" && <PastaStages model={model} onChange={update} />}
      <ThreatTable model={model} onChange={update} />
      <Elements model={model} onChange={update} />
      {model.permissions.can_edit && <NewThreat model={model} onChange={update} />}
    </div>
  );
}

const STRIDE_NAME: Record<string, string> = {
  S: "Spoofing",
  T: "Tampering",
  R: "Repudiation",
  I: "Information disclosure",
  D: "Denial of service",
  E: "Elevation of privilege",
  LLM: "LLM (OWASP Top 10 for LLM)",
};

type Change = (data: ThreatModelDetail) => void;

function ThreatTable({ model, onChange }: { model: ThreatModelDetail; onChange: Change }) {
  const [show, setShow] = useState<"carrying" | "all">("all");
  const [q, setQ] = useState("");
  const needle = q.trim().toLowerCase();
  const rows = model.threats.filter(
    (t) =>
      !t.retired &&
      (show === "all" || CARRYING.includes(t.status)) &&
      (!needle || t.ref.toLowerCase().includes(needle) || t.title.toLowerCase().includes(needle) || t.controls.some((c) => c.ref.toLowerCase().includes(needle))),
  );
  return (
    <section aria-labelledby="threats-heading" className="space-y-3">
      <h2 id="threats-heading" className="text-base font-semibold">
        Threats
      </h2>
      <div className="flex flex-wrap items-end gap-3">
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Show</span>
          <select value={show} onChange={(e) => setShow(e.target.value as "carrying" | "all")} className={selectBox}>
            <option value="all">All threats</option>
            <option value="carrying">Carrying risk</option>
          </select>
        </label>
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Search</span>
          <input
            type="search"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            maxLength={100}
            placeholder="Threat, ID or control"
            className="w-56 rounded border border-line bg-canvas px-2 py-1.5 text-sm"
          />
        </label>
      </div>
      <div className="overflow-x-auto rounded-md border border-line">
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Threats in this model</caption>
          <thead className="bg-surface text-xs text-ink-muted">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">Threat</th>
              <th scope="col" className="px-3 py-2 font-medium">STRIDE</th>
              <th scope="col" className="px-3 py-2 text-right font-medium">L × I</th>
              <th scope="col" className="px-3 py-2 font-medium">Controls</th>
              <th scope="col" className="px-3 py-2 font-medium">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {rows.map((t) => (
              <ThreatRow key={t.id} threat={t} model={model} onChange={onChange} />
            ))}
            {!rows.length && (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-center text-ink-muted">
                  No threats match.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function ThreatRow({ threat: t, model, onChange }: { threat: Threat; model: ThreatModelDetail; onChange: Change }) {
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);

  async function setStatus(status: ThreatStatus) {
    setBusy(true);
    setError(null);
    try {
      onChange(await updateThreat(model.id, t.id, { version: t.version, status }));
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <tr>
      <td className="max-w-md px-3 py-2">
        <span className="font-mono text-xs text-ink-muted">{t.ref}</span> <span className="break-words">{t.title}</span>
        {t.mitigation && <span className="mt-0.5 block break-words text-xs text-ink-muted">{t.mitigation}</span>}
        {error && <FormError error={error} />}
      </td>
      <td className="px-3 py-2 font-mono text-xs">{t.stride}</td>
      <td className={`px-3 py-2 text-right tabular-nums ${t.risk >= 6 ? "font-medium" : ""}`}>
        {t.likelihood}×{t.impact}
        <span className="block text-xs text-ink-muted">{t.risk}</span>
      </td>
      <td className="px-3 py-2 text-xs">
        {t.controls.length ? (
          <ul className="space-y-0.5">
            {t.controls.map((c) => (
              <li key={c.ref} title={c.title} className={c.status === "implemented" ? "text-ink" : "text-ink-muted"}>
                <span className="font-mono">{c.ref}</span>
                {c.status === "planned" && ` (P${c.phase})`}
              </li>
            ))}
          </ul>
        ) : (
          <span className="font-medium text-fail">None</span>
        )}
      </td>
      <td className="px-3 py-2">
        {model.permissions.can_edit ? (
          <select
            aria-label={`Status of ${t.ref}`}
            value={t.status}
            disabled={busy}
            onChange={(e) => void setStatus(e.target.value as ThreatStatus)}
            className={selectBox}
          >
            {THREAT_STATUSES.map((s) => (
              <option key={s} value={s}>
                {threatStatusLabel(s)}
              </option>
            ))}
          </select>
        ) : (
          <ThreatStatusBadge status={t.status} />
        )}
        {t.status_text && t.status_text !== threatStatusLabel(t.status) && (
          <span className="mt-1 block max-w-xs break-words text-xs text-ink-muted">{t.status_text}</span>
        )}
      </td>
    </tr>
  );
}

function Elements({ model, onChange }: { model: ThreatModelDetail; onChange: Change }) {
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);

  async function add(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const form = new FormData(formEl);
    const kind = String(form.get("kind")) as ElementKind;
    const boundaries = String(form.get("boundaries") ?? "")
      .split(",")
      .map((s) => s.trim().toUpperCase())
      .filter(Boolean);
    setBusy(true);
    setError(null);
    try {
      onChange(
        await addElement(model.id, {
          kind,
          name: String(form.get("name")).trim(),
          description: String(form.get("description")).trim(),
          boundaries: kind === "flow" ? boundaries : [],
        }),
      );
      formEl.reset();
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  async function retire(elementId: string) {
    try {
      onChange(await updateElement(model.id, elementId, { retired: true }));
    } catch (err) {
      setError(asApiError(err));
    }
  }

  return (
    <section aria-labelledby="elements-heading" className="space-y-4">
      <h2 id="elements-heading" className="text-base font-semibold">
        Model
      </h2>
      <div className="grid gap-4 md:grid-cols-2">
        {ELEMENT_KINDS.map((kind) => {
          const items = model.elements.filter((e) => e.kind === kind && !e.retired);
          return (
            <div key={kind} className="rounded-md border border-line bg-surface p-4">
              <h3 className="mb-2 text-sm font-semibold">{ELEMENT_LABEL[kind]}</h3>
              {!items.length && <p className="text-sm text-ink-muted">None recorded.</p>}
              <ul className="space-y-2">
                {items.map((e) => (
                  <li key={e.id} className="text-sm">
                    <span className="font-mono text-xs text-ink-muted">{e.ref}</span> <span className="break-words">{e.name}</span>
                    {e.boundaries.length > 0 && <span className="text-xs text-ink-muted"> · crosses {e.boundaries.join(", ")}</span>}
                    {e.description && e.description !== e.name && (
                      <span className="mt-0.5 block break-words text-xs text-ink-muted">{e.description}</span>
                    )}
                    {e.threats.length > 0 && <span className="block text-xs text-ink-muted">Threats: {e.threats.join(", ")}</span>}
                    {model.permissions.can_edit && (
                      <button type="button" onClick={() => void retire(e.id)} className="ml-2 text-xs text-accent hover:underline" aria-label={`Retire ${e.ref}`}>
                        Retire
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </div>
      {model.permissions.can_edit && (
        <form onSubmit={(e) => void add(e)} className="grid gap-3 rounded-md border border-line p-4 sm:grid-cols-4" aria-label="Add to the model">
          <label className="space-y-1 text-sm">
            <span className="block text-ink-muted">Add</span>
            <select name="kind" className={`${selectBox} w-full`}>
              {ELEMENT_KINDS.map((k) => (
                <option key={k} value={k}>
                  {ELEMENT_LABEL[k].replace(/s$/, "")}
                </option>
              ))}
            </select>
          </label>
          <label className="space-y-1 text-sm">
            <span className="block text-ink-muted">Name</span>
            <input name="name" required maxLength={300} className={textArea} />
          </label>
          <label className="space-y-1 text-sm">
            <span className="block text-ink-muted">Description</span>
            <input name="description" maxLength={4000} className={textArea} />
          </label>
          <label className="space-y-1 text-sm">
            <span className="block text-ink-muted">Boundaries crossed (flows)</span>
            <input name="boundaries" placeholder="TB1, TB2" maxLength={60} className={textArea} />
          </label>
          <div className="sm:col-span-4">
            <FormError error={error} />
            <Button type="submit" variant="secondary" busy={busy} className="mt-2">
              Add
            </Button>
          </div>
        </form>
      )}
    </section>
  );
}

function NewThreat({ model, onChange }: { model: ThreatModelDetail; onChange: Change }) {
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const list = (value: FormDataEntryValue | null) =>
    String(value ?? "")
      .split(",")
      .map((s) => s.trim().toUpperCase())
      .filter(Boolean);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const form = new FormData(formEl);
    setBusy(true);
    setError(null);
    try {
      onChange(
        await addThreat(model.id, {
          title: String(form.get("title")).trim(),
          stride: String(form.get("stride")).trim().toUpperCase(),
          owasp: String(form.get("owasp")).trim(),
          boundaries: list(form.get("boundaries")),
          likelihood: Number(form.get("likelihood")),
          impact: Number(form.get("impact")),
          mitigation: String(form.get("mitigation")).trim(),
          status: String(form.get("status")) as ThreatStatus,
          controls: list(form.get("controls")),
        }),
      );
      formEl.reset();
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  const score = (name: string, label: string) => (
    <label className="space-y-1 text-sm">
      <span className="block text-ink-muted">{label}</span>
      <select name={name} defaultValue="2" className={`${selectBox} w-full`}>
        <option value="1">1 · Low</option>
        <option value="2">2 · Medium</option>
        <option value="3">3 · High</option>
      </select>
    </label>
  );

  return (
    <section aria-labelledby="new-threat" className="rounded-md border border-line bg-surface p-5">
      <h2 id="new-threat" className="mb-3 text-base font-semibold">
        Add a threat
      </h2>
      <form onSubmit={(e) => void submit(e)} className="grid gap-3 sm:grid-cols-4">
        <label className="space-y-1 text-sm sm:col-span-4">
          <span className="block text-ink-muted">Threat</span>
          <input name="title" required maxLength={300} className={textArea} />
        </label>
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">STRIDE (e.g. I/T) or LLM01</span>
          <input name="stride" required maxLength={16} pattern="([STRIDEstride](/[STRIDEstride]){0,5}|[Ll][Ll][Mm][0-9]{2})" className={textArea} />
        </label>
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">OWASP</span>
          <input name="owasp" maxLength={64} placeholder="API1, A03" className={textArea} />
        </label>
        {score("likelihood", "Likelihood")}
        {score("impact", "Impact")}
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Status</span>
          <select name="status" defaultValue="open" className={`${selectBox} w-full`}>
            {THREAT_STATUSES.map((s) => (
              <option key={s} value={s}>
                {threatStatusLabel(s)}
              </option>
            ))}
          </select>
        </label>
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Boundaries</span>
          <input name="boundaries" placeholder="TB1" maxLength={60} className={textArea} />
        </label>
        <label className="space-y-1 text-sm sm:col-span-2">
          <span className="block text-ink-muted">Controls (catalogue IDs)</span>
          <input name="controls" placeholder="C-API-04, C-WAF-01" maxLength={300} className={textArea} />
        </label>
        <label className="space-y-1 text-sm sm:col-span-4">
          <span className="block text-ink-muted">Mitigation</span>
          <textarea name="mitigation" rows={2} maxLength={4000} className={textArea} />
        </label>
        <div className="sm:col-span-4">
          <FormError error={error} />
          <Button type="submit" busy={busy} className="mt-2">
            Add threat
          </Button>
        </div>
      </form>
    </section>
  );
}

function PastaStages({ model, onChange }: { model: ThreatModelDetail; onChange: Change }) {
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const pasta = Object.fromEntries(PASTA_STAGES.map((s) => [s, String(form.get(s) ?? "").trim()]));
    setBusy(true);
    setError(null);
    try {
      onChange(await updateThreatModel(model.id, { version: model.version, pasta }));
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="pasta-heading" className="space-y-3">
      <h2 id="pasta-heading" className="text-base font-semibold">
        PASTA stages
      </h2>
      <form onSubmit={(e) => void save(e)} className="grid gap-3 md:grid-cols-2">
        {PASTA_STAGES.map((s) => (
          <label key={`${s}-${model.version}`} className="space-y-1 text-sm">
            <span className="block text-ink-muted">{STAGE_LABEL[s]}</span>
            <textarea
              name={s}
              rows={3}
              maxLength={4000}
              defaultValue={model.pasta[s] ?? ""}
              readOnly={!model.permissions.can_edit}
              className={textArea}
            />
          </label>
        ))}
        {model.permissions.can_edit && (
          <div className="md:col-span-2">
            <FormError error={error} />
            <Button type="submit" variant="secondary" busy={busy} className="mt-2">
              Save stages
            </Button>
          </div>
        )}
      </form>
    </section>
  );
}
