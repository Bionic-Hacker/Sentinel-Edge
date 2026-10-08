import { useEffect, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { Button, FormError } from "../../components/forms";
import { formatTime } from "../../components/secops";
import type { ApiError } from "../../lib/api/client";
import { downloadSbom, getSbom, listSboms } from "../../lib/api/vulnerabilities";
import type { SbomDetail, SbomList, SbomSummary } from "../../lib/types";
import { asApiError } from "../auth/LoginPage";

const PAGE = 100;

export function SbomPage() {
  const [params, setParams] = useSearchParams();
  const [list, setList] = useState<{ data: SbomList | null; error: ApiError | null } | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    listSboms(controller.signal)
      .then((data) => setList({ data, error: null }))
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setList({ data: null, error: asApiError(err) });
      });
    return () => controller.abort();
  }, []);

  const sboms = list?.data?.items ?? [];
  const selectedId = params.get("sbom") ?? sboms[0]?.id ?? null;
  const selected = sboms.find((s) => s.id === selectedId) ?? null;

  return (
    <div className="max-w-7xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Software bill of materials</h1>
        <p className="mt-1 max-w-prose text-ink-muted">
          Every component in the API image, the web image and the source tree, as Syft recorded it in CycloneDX at the
          last imported scan. Known vulnerabilities in these components are on the Vulnerabilities page.
        </p>
      </header>
      {list?.error && <FormError error={list.error} />}
      {!list && <p className="text-sm text-ink-muted">Loading SBOMs…</p>}
      {list?.data && !sboms.length && (
        <p className="rounded-md border border-line bg-surface px-4 py-3 text-sm text-ink-muted">
          No SBOM imported yet. Run <code className="font-mono text-ink">make scan</code>, then{" "}
          <code className="font-mono text-ink">make scan-import</code>.
        </p>
      )}
      {sboms.length > 0 && (
        <ul className="grid grid-cols-1 gap-3 md:grid-cols-3" aria-label="SBOMs">
          {sboms.map((s) => (
            <li key={s.id}>
              <button
                type="button"
                aria-pressed={s.id === selectedId}
                onClick={() => setParams({ sbom: s.id }, { replace: true })}
                className={`w-full rounded-md border p-4 text-left ${s.id === selectedId ? "border-accent bg-raised" : "border-line bg-surface hover:border-accent/60"}`}
              >
                <span className="block text-sm font-medium capitalize">{s.artifact}</span>
                <span className="mt-0.5 block break-all text-xs text-ink-muted">{s.subject}</span>
                <span className="mt-2 block text-2xl font-semibold">{s.component_count}</span>
                <span className="block text-xs text-ink-muted">
                  components · {s.scan.reference}, {formatTime(s.created_at)}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
      {selected && <Components key={selected.id} sbom={selected} />}
    </div>
  );
}

function Components({ sbom }: { sbom: SbomSummary }) {
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);
  const key = `${q}|${offset}`;
  const [result, setResult] = useState<{ key: string; data: SbomDetail | null; error: ApiError | null } | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState<ApiError | null>(null);
  const current = result?.key === key ? result : null;

  useEffect(() => {
    const controller = new AbortController();
    getSbom(sbom.id, { ...(q ? { q } : {}), limit: PAGE, offset }, controller.signal)
      .then((data) => setResult({ key, data, error: null }))
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setResult({ key, data: null, error: asApiError(err) });
      });
    return () => controller.abort();
  }, [sbom.id, q, offset, key]);

  function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setQ(String(new FormData(event.currentTarget).get("q") ?? "").trim().slice(0, 100));
    setOffset(0);
  }

  async function download() {
    setDownloading(true);
    setDownloadError(null);
    try {
      const blob = await downloadSbom(sbom.id);
      // A same-origin blob URL handed to a temporary download link; revoked straight after.
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `sbom-${sbom.artifact}.cdx.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setDownloadError(asApiError(err));
    } finally {
      setDownloading(false);
    }
  }

  const data = current?.data;
  const total = data?.components_total ?? 0;
  return (
    <section aria-labelledby="components-heading" className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 id="components-heading" className="text-base font-semibold capitalize">
            {sbom.artifact} components
          </h2>
          <p className="text-xs text-ink-muted">
            {sbom.format} {sbom.spec_version} · SHA-256 <code className="font-mono">{sbom.document_sha256.slice(0, 16)}…</code>
          </p>
        </div>
        <div className="flex flex-wrap items-end gap-2">
          <form onSubmit={search} role="search" className="flex items-end gap-2">
            <label className="space-y-1 text-sm">
              <span className="block text-ink-muted">Search</span>
              <input name="q" type="search" maxLength={100} placeholder="Name or package URL" className="w-56 rounded border border-line bg-canvas px-2 py-1.5 text-sm" />
            </label>
            <Button type="submit" variant="secondary">
              Search
            </Button>
          </form>
          <Button variant="secondary" busy={downloading} onClick={() => void download()}>
            Download CycloneDX
          </Button>
        </div>
      </div>
      <FormError error={downloadError ?? current?.error ?? null} />
      <div className="overflow-x-auto rounded-md border border-line">
        <table className="w-full text-left text-sm">
          <caption className="sr-only">{`Components of the ${sbom.artifact} SBOM`}</caption>
          <thead className="bg-surface text-xs text-ink-muted">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">Component</th>
              <th scope="col" className="px-3 py-2 font-medium">Version</th>
              <th scope="col" className="px-3 py-2 font-medium">Type</th>
              <th scope="col" className="px-3 py-2 font-medium">Licenses</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {data?.components.map((c, i) => (
              <tr key={`${c.purl ?? c.name}-${i}`}>
                <td className="max-w-md px-3 py-2">
                  <span className="break-words">{c.name}</span>
                  {c.purl && <span className="mt-0.5 block break-all font-mono text-xs text-ink-muted">{c.purl}</span>}
                </td>
                <td className="break-all px-3 py-2 font-mono text-xs">{c.version ?? "-"}</td>
                <td className="px-3 py-2 text-ink-muted">{c.type ?? "-"}</td>
                <td className="px-3 py-2 text-xs text-ink-muted">{c.licenses.length ? c.licenses.join(", ") : "Not declared"}</td>
              </tr>
            ))}
            {!current && (
              <tr>
                <td colSpan={4} className="px-3 py-6 text-center text-ink-muted">
                  Loading components…
                </td>
              </tr>
            )}
            {data && !data.components.length && (
              <tr>
                <td colSpan={4} className="px-3 py-6 text-center text-ink-muted">
                  No components match.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {data && total > PAGE && (
          <div className="flex items-center justify-between gap-3 border-t border-line p-3 text-sm">
            <span className="text-ink-muted tabular-nums">
              {offset + 1} to {Math.min(offset + PAGE, total)} of {total}
            </span>
            <span className="flex gap-2">
              <Button variant="secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
                Previous
              </Button>
              <Button variant="secondary" disabled={offset + PAGE >= total} onClick={() => setOffset(offset + PAGE)}>
                Next
              </Button>
            </span>
          </div>
        )}
      </div>
    </section>
  );
}
