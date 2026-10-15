import { PageHeader } from "../../components/page";
import { useCallback } from "react";
import { useCapabilities } from "../../app/capabilities-context";
import { useCurrentUser } from "../../app/auth-context";
import { MODULES } from "../../app/modules";
import { CapabilityTable } from "../../components/CapabilityTable";
import { FormError } from "../../components/forms";
import { ProvenanceBadge } from "../../components/ProvenanceBadge";
import { SeverityBadge, StatTile } from "../../components/secops";
import { listCertificates, type Certificate } from "../../lib/api/edge";
import type { Role } from "../../lib/types";
import { useApi } from "../../lib/useApi";

const READERS: readonly Role[] = ["ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const MODULE = MODULES.find((m) => m.path === "/certificates");
const CONDITION: Record<string, string> = {
  expiring: "Expiring",
  expired: "Expired",
  renewal_failed: "Renewal failed",
  revoked: "Revoked",
  failed: "Failed",
  validation_timed_out: "Validation timed out",
};

const day = (iso: string | null) => (iso ? iso.slice(0, 10) : "—");

/** ACM certificates read live from AWS (ADR-0029); expiry raises certificate events. */
export function CertificatesPage() {
  const user = useCurrentUser();
  return (
    <div className="max-w-7xl space-y-8">
      <PageHeader
        title="Certificates"
        summary="The platform's TLS certificates, read live from AWS Certificate Manager."
        about={
          <p>
            The platform's TLS certificates in AWS Certificate Manager, read live: status, expiry and renewal. A certificate that is expiring, expired or failed to renew raises a certificate event on the Threats page.
          </p>
        }
      />
      {READERS.includes(user.role) ? (
        <CertificateInventory />
      ) : (
        <p className="max-w-prose text-ink-muted">
          Certificates are available to administrators, security engineers, analysts and viewers.
        </p>
      )}
      <ModuleCapabilities />
    </div>
  );
}

function CertificateInventory() {
  const load = useCallback((signal: AbortSignal) => listCertificates(signal), []);
  const result = useApi(load);
  if (result.state === "loading") return <p className="text-sm text-ink-muted">Reading certificates…</p>;
  if (result.state === "error") return <FormError error={result.error} />;
  const { enabled, regions, items, error } = result.data;
  if (!enabled) {
    return (
      <p className="max-w-prose text-sm text-ink-muted">
        Certificate monitoring reads ACM in the AWS deploy window. This environment has no AWS account connected, so there
        are no certificates to read.
      </p>
    );
  }
  const attention = items.filter((c) => c.condition !== null);
  const soonest = items.find((c) => c.days_left !== null);
  return (
    <section aria-labelledby="acm" className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <h2 id="acm" className="text-lg font-semibold">
          AWS Certificate Manager
        </h2>
        <ProvenanceBadge provenance="REAL_AWS" />
        <span className="text-sm text-ink-muted">Regions: {regions.join(", ")}</span>
      </div>
      {error && <p className="text-sm text-fail">{error}</p>}
      <dl className="grid gap-3 sm:grid-cols-3">
        <StatTile label="Certificates" value={items.length} />
        <StatTile label="Need attention" value={attention.length} tone={attention.length ? "fail" : "ok"} />
        <StatTile
          label="Soonest expiry"
          value={soonest ? `${soonest.days_left} days` : "—"}
          note={soonest ? soonest.domain : undefined}
          tone={soonest && soonest.days_left !== null && soonest.days_left <= 30 ? "warn" : undefined}
        />
      </dl>
      <div className="overflow-x-auto rounded-md border border-line">
        <table className="w-full min-w-[860px] text-left text-sm">
          <caption className="sr-only">Certificates in AWS Certificate Manager</caption>
          <thead className="bg-surface text-xs text-ink-muted">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">Domain</th>
              <th scope="col" className="px-3 py-2 font-medium">Region</th>
              <th scope="col" className="px-3 py-2 font-medium">Status</th>
              <th scope="col" className="px-3 py-2 font-medium">Expires</th>
              <th scope="col" className="px-3 py-2 font-medium">Renewal</th>
              <th scope="col" className="px-3 py-2 font-medium">In use by</th>
              <th scope="col" className="px-3 py-2 font-medium">Key</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {items.length === 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-4 text-center text-ink-muted">
                  No certificates in these Regions.
                </td>
              </tr>
            )}
            {items.map((c) => (
              <CertificateRow key={c.arn} cert={c} />
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function CertificateRow({ cert }: { cert: Certificate }) {
  const others = cert.alternative_names.filter((n) => n !== cert.domain);
  return (
    <tr>
      <td className="px-3 py-2.5">
        <div className="font-medium text-ink">{cert.domain}</div>
        {others.length > 0 && <div className="text-xs text-ink-muted">also {others.join(", ")}</div>}
      </td>
      <td className="px-3 py-2.5 font-mono text-xs">{cert.region}</td>
      <td className="px-3 py-2.5">
        {cert.condition && cert.severity ? (
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={cert.severity} />
            <span>{CONDITION[cert.condition] ?? cert.condition}</span>
          </span>
        ) : (
          <span className={cert.status === "ISSUED" ? "text-ok" : "text-ink-muted"}>
            {cert.status === "ISSUED" ? "Issued" : cert.status.replaceAll("_", " ").toLowerCase()}
          </span>
        )}
      </td>
      <td className="whitespace-nowrap px-3 py-2.5">
        {day(cert.not_after)}
        {cert.days_left !== null && <span className="block text-xs text-ink-muted">{cert.days_left} days left</span>}
      </td>
      <td className="px-3 py-2.5 text-xs text-ink-muted">
        {cert.renewal_eligibility === "ELIGIBLE" ? "Automatic (ACM)" : "Not eligible"}
        {cert.renewal_status && <span className="block">{cert.renewal_status.replaceAll("_", " ").toLowerCase()}</span>}
      </td>
      <td className="px-3 py-2.5 tabular-nums">{cert.in_use_by}</td>
      <td className="px-3 py-2.5 font-mono text-xs">{cert.key_algorithm ?? "—"}</td>
    </tr>
  );
}

function ModuleCapabilities() {
  const caps = useCapabilities();
  if (!MODULE || caps.state !== "ready") return null;
  const items = caps.data.filter((c) => MODULE.capabilityKeys.includes(c.key));
  if (!items.length) return null;
  return (
    <section className="space-y-3">
      <CapabilityTable caption="Certificate capabilities" items={items} />
    </section>
  );
}
