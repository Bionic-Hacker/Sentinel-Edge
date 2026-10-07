import { useCallback } from "react";
import { getHealth } from "../lib/api/platform";
import { useApi } from "../lib/useApi";

/** Live API reachability, from GET /api/v1/health. */
export function ApiStatus() {
  const load = useCallback((signal: AbortSignal) => getHealth(signal), []);
  const health = useApi(load);

  if (health.state === "loading") {
    return <span className="text-sm text-ink-muted">Checking API…</span>;
  }
  if (health.state === "error") {
    return (
      <span className="flex items-center gap-2 text-sm text-fail" role="status">
        <span aria-hidden="true" className="size-2 rounded-full bg-fail" />
        API unreachable
      </span>
    );
  }
  return (
    <span className="flex items-center gap-2 text-sm text-ink-muted" role="status">
      <span aria-hidden="true" className="size-2 rounded-full bg-ok" />
      API online <span className="font-mono text-xs">v{health.data.version}</span>
    </span>
  );
}
