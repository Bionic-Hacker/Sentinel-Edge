import type { ModuleDef } from "../app/modules";
import { useCapabilities } from "../app/capabilities-context";
import { CapabilityTable } from "../components/CapabilityTable";
import { ErrorPanel } from "./ErrorPanel";

/** Honest placeholder: states the module's purpose and the real status of what backs it. */
export function ModulePage({ module }: { module: ModuleDef }) {
  const caps = useCapabilities();

  return (
    <div className="max-w-5xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">{module.label}</h1>
        <p className="mt-1 max-w-prose text-ink-muted">{module.purpose}</p>
        <p className="mt-3 text-sm text-ink-muted">
          This module is built in phase {module.phase}. It shows no data until then, rather than
          placeholder figures.
        </p>
      </header>
      <section aria-labelledby="module-caps" className="space-y-3">
        <h2 id="module-caps" className="text-lg font-semibold">Capabilities</h2>
        {caps.state === "loading" && <p className="text-sm text-ink-muted">Loading capabilities…</p>}
        {caps.state === "error" && <ErrorPanel error={caps.error} />}
        {caps.state === "ready" && (
          <CapabilityTable
            caption={`Capabilities for ${module.label}`}
            items={caps.data.filter((c) => module.capabilityKeys.includes(c.key))}
          />
        )}
      </section>
    </div>
  );
}
