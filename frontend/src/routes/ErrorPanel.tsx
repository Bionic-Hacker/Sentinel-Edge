import type { ApiError } from "../lib/api/client";

export function ErrorPanel({ error }: { error: ApiError }) {
  return (
    <div role="alert" className="rounded-md border border-fail/50 bg-fail/10 px-4 py-3 text-sm">
      <p className="font-medium text-ink">{error.message}.</p>
      <p className="mt-1 text-ink-muted">
        Start the API with <code className="font-mono">make dev</code>, then reload this page.
        {error.correlationId && (
          <>
            {" "}Reference <code className="font-mono">{error.correlationId}</code> when checking API logs.
          </>
        )}
      </p>
    </div>
  );
}
