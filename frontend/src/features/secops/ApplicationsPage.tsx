import { useEffect, useState, type FormEvent } from "react";
import { useCapabilities } from "../../app/capabilities-context";
import { useCurrentUser } from "../../app/auth-context";
import { MODULES } from "../../app/modules";
import { CapabilityTable } from "../../components/CapabilityTable";
import { Button, FormError, Notice } from "../../components/forms";
import type { ApiError } from "../../lib/api/client";
import { createApplication, listApplicationOwners, listApplications, updateApplication } from "../../lib/api/secops";
import {
  APP_ENVIRONMENTS,
  CRITICALITIES,
  type AppEnvironment,
  type Application,
  type Criticality,
  type Measure,
  type Person,
  type Role,
} from "../../lib/types";
import { asApiError } from "../auth/LoginPage";

const EDITORS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER"];

// The same rules the API enforces (backend/app/schemas/applications.py), checked first so the form
// can say which field is wrong.
const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** A DNS hostname only: no scheme, port, path or credentials. Empty means "no domain". */
export function hostnameProblem(raw: string): string | null {
  const value = raw.trim().toLowerCase().replace(/\.$/, "");
  if (!value) return null;
  if (value.length <= 253 && value.split(".").every((label) => HOST_LABEL.test(label))) return null;
  return "Enter a hostname such as app.example.com, without a scheme, port or path.";
}

export function slugProblem(raw: string): string | null {
  return SLUG.test(raw.trim())
    ? null
    : "Use 1 to 63 lowercase letters, digits and hyphens, starting with a letter or digit.";
}
const MODULE = MODULES.find((m) => m.path === "/applications");

export function ApplicationsPage() {
  const user = useCurrentUser();
  const canEdit = EDITORS.includes(user.role);
  const [apps, setApps] = useState<Application[] | null>(null);
  const [owners, setOwners] = useState<Person[]>([]);
  const [error, setError] = useState<ApiError | null>(null);
  const [registering, setRegistering] = useState(false);
  const [registered, setRegistered] = useState<string | null>(null);
  const [version, setVersion] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    listApplications(controller.signal)
      .then((items) => {
        setApps(items);
        setError(null);
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(asApiError(err));
      });
    if (canEdit) {
      listApplicationOwners(controller.signal)
        .then(setOwners)
        .catch(() => setOwners([]));
    }
    return () => controller.abort();
  }, [canEdit, version]);

  return (
    <div className="max-w-7xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Applications</h1>
          <p className="mt-1 max-w-prose text-ink-muted">
            The applications SentinelEdge protects, with their owners and criticality. SentinelEdge is the first: its
            figures are measured live. Values that need a later phase say so rather than show a made-up number.
          </p>
        </div>
        {canEdit && !registering && (
          <Button
            onClick={() => {
              setRegistered(null);
              setRegistering(true);
            }}
          >
            Register an application
          </Button>
        )}
      </header>
      {user.role === "DEVELOPER" && (
        <p className="text-sm text-ink-muted">You see the applications you own. Ask a security engineer to assign you as owner.</p>
      )}
      {registering && (
        <RegisterForm
          owners={owners}
          onDone={(name) => {
            setRegistering(false);
            setRegistered(name);
            setVersion((n) => n + 1);
          }}
          onCancel={() => setRegistering(false)}
        />
      )}
      {registered && <Notice>{registered} registered.</Notice>}
      {error && <FormError error={error} />}
      {!apps && !error && <p className="text-sm text-ink-muted">Loading applications…</p>}
      {apps && (
        <ul className="space-y-4">
          {apps.map((app) => (
            <ApplicationCard
              key={`${app.id}-${app.version}`}
              app={app}
              canEdit={canEdit}
              owners={owners}
              onChange={(next) => setApps((list) => list?.map((a) => (a.id === next.id ? next : a)) ?? null)}
            />
          ))}
          {!apps.length && <li className="text-sm text-ink-muted">No applications to show.</li>}
        </ul>
      )}
      <ModuleCapabilities />
    </div>
  );
}

const MEASURE_LABELS: [keyof Application, string][] = [
  ["api_count", "API endpoints"],
  ["open_incidents", "Open incidents"],
  ["security_events_24h", "Security events (24 h)"],
  ["waf_status", "WAF"],
  ["certificate_status", "Certificate"],
  ["security_score", "Security score"],
  ["last_scan", "Last scan"],
  ["vulnerability_count", "Vulnerabilities"],
];

function MeasureValue({ measure }: { measure: Measure }) {
  if (measure.status === "measured") {
    return (
      <span className="text-base font-semibold [font-feature-settings:'tnum'_0]" title={measure.note}>
        {measure.value}
      </span>
    );
  }
  return (
    <span className="text-xs text-ink-muted" title={measure.note}>
      {measure.status === "planned" ? measure.note : "Not connected"}
    </span>
  );
}

function ApplicationCard({
  app,
  canEdit,
  owners,
  onChange,
}: {
  app: Application;
  canEdit: boolean;
  owners: Person[];
  onChange: (app: Application) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [domainError, setDomainError] = useState<string | null>(null);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const owner = String(form.get("owner") ?? "");
    const domain = String(form.get("domain") ?? "").trim();
    const domainError = hostnameProblem(domain);
    setDomainError(domainError);
    if (domainError) return;
    setBusy(true);
    setError(null);
    try {
      onChange(
        await updateApplication(app.id, {
          version: app.version,
          criticality: String(form.get("criticality")) as Criticality,
          environment: String(form.get("environment")) as AppEnvironment,
          ...(owner ? { owner_id: owner } : { clear_owner: true }),
          ...(domain ? { domain } : {}),
          ...(app.is_platform ? {} : { status: form.get("retired") ? ("retired" as const) : ("active" as const) }),
        }),
      );
      setEditing(false);
    } catch (err) {
      setError(asApiError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <li className={`rounded-md border border-line bg-surface p-5 ${app.status === "retired" ? "opacity-70" : ""}`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold">
            {app.name} <span className="font-mono text-xs font-normal text-ink-muted">{app.slug}</span>
          </h2>
          <p className="mt-0.5 text-sm text-ink-muted">{app.description || "No description."}</p>
          <p className="mt-1 text-xs text-ink-muted">
            {app.environment} · criticality {app.criticality} · {app.domain ?? "no domain"} · owner{" "}
            {app.owner ? app.owner.display_name : "unassigned"}
            {app.status === "retired" ? " · retired" : ""}
            {app.is_platform ? " · this platform" : ""}
          </p>
        </div>
        {canEdit && !editing && (
          <Button variant="secondary" onClick={() => setEditing(true)}>
            Edit
          </Button>
        )}
      </div>
      <dl className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-8">
        {MEASURE_LABELS.map(([key, label]) => (
          <div key={key} className="rounded border border-line px-3 py-2">
            <dt className="text-xs text-ink-muted">{label}</dt>
            <dd className="mt-1">
              <MeasureValue measure={app[key] as Measure} />
            </dd>
          </div>
        ))}
      </dl>
      {editing && (
        <form
          noValidate
          onSubmit={(e) => void save(e)}
          className="mt-4 grid grid-cols-1 gap-3 rounded border border-line p-3 md:grid-cols-4"
          aria-label={`Edit ${app.name}`}
        >
          <Choice name="environment" label="Environment" value={app.environment} options={APP_ENVIRONMENTS} />
          <Choice name="criticality" label="Criticality" value={app.criticality} options={CRITICALITIES} />
          <label className="space-y-1 text-sm">
            <span className="block text-ink-muted">Owner</span>
            <select name="owner" defaultValue={app.owner?.id ?? ""} className="w-full rounded border border-line bg-canvas px-2 py-1.5 text-sm">
              <option value="">Unassigned</option>
              {owners.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.display_name} ({o.role.replace("_", " ").toLowerCase()})
                </option>
              ))}
            </select>
          </label>
          <div className="space-y-1 text-sm">
            <label className="block space-y-1">
              <span className="block text-ink-muted">Domain</span>
              <input
                name="domain"
                defaultValue={app.domain ?? ""}
                aria-invalid={domainError ? true : undefined}
                aria-describedby={domainError ? `domain-error-${app.id}` : undefined}
                className="w-full rounded border border-line bg-canvas px-2 py-1.5 text-sm"
              />
            </label>
            <FieldError id={`domain-error-${app.id}`} message={domainError} />
          </div>
          {!app.is_platform && (
            <label className="flex items-center gap-2 text-sm md:col-span-4">
              <input type="checkbox" name="retired" defaultChecked={app.status === "retired"} />
              Retired (kept in the inventory, never deleted)
            </label>
          )}
          <div className="md:col-span-4">
            <FormError error={error} />
          </div>
          <div className="flex gap-2 md:col-span-4">
            <Button type="submit" busy={busy}>
              Save
            </Button>
            <Button type="button" variant="secondary" onClick={() => setEditing(false)}>
              Cancel
            </Button>
          </div>
        </form>
      )}
    </li>
  );
}

function Choice({ name, label, value, options }: { name: string; label: string; value: string; options: readonly string[] }) {
  return (
    <label className="space-y-1 text-sm">
      <span className="block text-ink-muted">{label}</span>
      <select name={name} defaultValue={value} className="w-full rounded border border-line bg-canvas px-2 py-1.5 text-sm capitalize">
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}

function FieldError({ id, message }: { id: string; message: string | null }) {
  if (!message) return null;
  return (
    <span id={id} className="block text-xs text-fail">
      {message}
    </span>
  );
}

interface RegisterProblems {
  name: string | null;
  slug: string | null;
  domain: string | null;
}

function RegisterForm({
  owners,
  onDone,
  onCancel,
}: {
  owners: Person[];
  onDone: (name: string) => void;
  onCancel: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [problems, setProblems] = useState<RegisterProblems>({ name: null, slug: null, domain: null });

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const owner = String(form.get("owner") ?? "");
    const domain = String(form.get("domain") ?? "").trim();
    const description = String(form.get("description") ?? "").trim();
    const found: RegisterProblems = {
      name: String(form.get("name") ?? "").trim() ? null : "Enter a name.",
      slug: slugProblem(String(form.get("slug") ?? "")),
      domain: hostnameProblem(domain),
    };
    setProblems(found);
    if (found.name || found.slug || found.domain) return;
    setBusy(true);
    setError(null);
    try {
      const app = await createApplication({
        slug: String(form.get("slug") ?? "").trim(),
        name: String(form.get("name") ?? "").trim(),
        environment: String(form.get("environment")) as AppEnvironment,
        criticality: String(form.get("criticality")) as Criticality,
        ...(owner ? { owner_id: owner } : {}),
        ...(domain ? { domain } : {}),
        ...(description ? { description } : {}),
      });
      onDone(app.name);
    } catch (err) {
      setError(asApiError(err));
      setBusy(false);
    }
  }

  return (
    <form
      noValidate
      onSubmit={(e) => void submit(e)}
      className="space-y-3 rounded-md border border-line bg-surface p-5"
      aria-label="Register an application"
    >
      <h2 className="text-base font-semibold">Register an application</h2>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <div className="space-y-1 text-sm">
          <label className="block space-y-1">
            <span className="block font-medium">Name</span>
            <input
              name="name"
              required
              maxLength={100}
              aria-invalid={problems.name ? true : undefined}
              aria-describedby={problems.name ? "register-name-error" : undefined}
              className="w-full rounded border border-line bg-canvas px-3 py-2 text-sm"
            />
          </label>
          <FieldError id="register-name-error" message={problems.name} />
        </div>
        <div className="space-y-1 text-sm">
          <label className="block space-y-1">
            <span className="block font-medium">Slug</span>
            <input
              name="slug"
              required
              maxLength={64}
              pattern="[a-z0-9][a-z0-9\-]{0,62}"
              title="Lowercase letters, digits and hyphens"
              aria-invalid={problems.slug ? true : undefined}
              aria-describedby={problems.slug ? "register-slug-error" : undefined}
              className="w-full rounded border border-line bg-canvas px-3 py-2 font-mono text-sm"
            />
          </label>
          <FieldError id="register-slug-error" message={problems.slug} />
        </div>
        <div className="space-y-1 text-sm">
          <label className="block space-y-1">
            <span className="block font-medium">Domain</span>
            <input
              name="domain"
              placeholder="app.example.com"
              aria-invalid={problems.domain ? true : undefined}
              aria-describedby={problems.domain ? "register-domain-error" : undefined}
              className="w-full rounded border border-line bg-canvas px-3 py-2 text-sm"
            />
          </label>
          <FieldError id="register-domain-error" message={problems.domain} />
        </div>
        <Choice name="environment" label="Environment" value="production" options={APP_ENVIRONMENTS} />
        <Choice name="criticality" label="Criticality" value="high" options={CRITICALITIES} />
        <label className="space-y-1 text-sm">
          <span className="block text-ink-muted">Owner</span>
          <select name="owner" defaultValue="" className="w-full rounded border border-line bg-canvas px-2 py-1.5 text-sm">
            <option value="">Unassigned</option>
            {owners.map((o) => (
              <option key={o.id} value={o.id}>
                {o.display_name} ({o.role.replace("_", " ").toLowerCase()})
              </option>
            ))}
          </select>
        </label>
      </div>
      <label className="block space-y-1 text-sm">
        <span className="block font-medium">Description</span>
        <textarea name="description" maxLength={500} rows={2} className="w-full rounded border border-line bg-canvas px-3 py-2 text-sm" />
      </label>
      <p className="text-xs text-ink-muted">
        The domain is recorded only. SentinelEdge never connects to it, and it starts monitoring an application only when
        its telemetry is connected in a later phase.
      </p>
      <FormError error={error} />
      <div className="flex gap-2">
        <Button type="submit" busy={busy}>
          Register
        </Button>
        <Button type="button" variant="secondary" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

function ModuleCapabilities() {
  const caps = useCapabilities();
  if (!MODULE || caps.state !== "ready") return null;
  const items = caps.data.filter((c) => MODULE.capabilityKeys.includes(c.key));
  if (!items.length) return null;
  return (
    <section aria-labelledby="app-caps" className="space-y-3">
      <h2 id="app-caps" className="text-lg font-semibold">
        Capabilities
      </h2>
      <CapabilityTable caption="Application inventory capabilities" items={items} />
    </section>
  );
}
