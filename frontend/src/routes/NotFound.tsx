import { Link } from "react-router-dom";

export function NotFound() {
  return (
    <div className="max-w-prose space-y-2">
      <h1 className="text-2xl font-semibold tracking-tight">Page not found</h1>
      <p className="text-ink-muted">
        This address doesn't match a SentinelEdge module.{" "}
        <Link to="/" className="text-accent underline underline-offset-2">Go to platform status</Link>.
      </p>
    </div>
  );
}
