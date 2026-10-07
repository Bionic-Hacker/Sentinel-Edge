import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "./auth-context";

/**
 * Client-side routing guard. This is a usability feature, not a security boundary: the API
 * enforces authentication and roles on every request regardless of what the UI shows.
 */
export function RequireAuth({ children, allowPending = false }: { children: ReactNode; allowPending?: boolean }) {
  const { state } = useAuth();
  const location = useLocation();

  if (state.status === "loading") {
    return (
      <div className="flex min-h-screen items-center justify-center text-sm text-ink-muted" role="status">
        Checking your session…
      </div>
    );
  }
  if (state.status === "anonymous") {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  if (!allowPending && state.user.pending_steps.length > 0) {
    return <Navigate to="/setup" replace />;
  }
  if (allowPending && state.user.pending_steps.length === 0) {
    return <Navigate to="/" replace />;
  }
  return <>{children}</>;
}

/** For /login and /forgot-password: signed-in users go straight to the app. */
export function PublicOnly({ children }: { children: ReactNode }) {
  const { state } = useAuth();
  if (state.status === "loading") return null;
  if (state.status === "authenticated") return <Navigate to="/" replace />;
  return <>{children}</>;
}

export function AuthCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-2">
          <img src="/favicon.svg" alt="" className="size-7" />
          <span className="text-lg font-semibold tracking-tight">SentinelEdge</span>
        </div>
        <div className="rounded-md border border-line bg-surface p-6">
          <h1 className="mb-5 text-xl font-semibold tracking-tight">{title}</h1>
          {children}
        </div>
      </div>
    </main>
  );
}
