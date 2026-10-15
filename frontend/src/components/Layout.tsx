import type { CSSProperties } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useAuth, useCurrentUser } from "../app/auth-context";
import { MODULES, backdropFor } from "../app/modules";
import { getEnvironment } from "../lib/api/edge";
import { useApi } from "../lib/useApi";
import { ApiStatus } from "./ApiStatus";
import { ThemeToggle } from "./ThemeToggle";

function UserMenu() {
  const user = useCurrentUser();
  const { logout } = useAuth();
  return (
    <div className="flex items-center gap-3 text-sm">
      <span className="text-right leading-tight">
        <span className="block text-ink">{user.display_name}</span>
        <span className="block text-xs text-ink-muted">
          {user.role.replace("_", " ").toLowerCase()}
        </span>
      </span>
      <ThemeToggle />
      <button
        type="button"
        onClick={() => void logout()}
        className="rounded border border-line px-2.5 py-1.5 text-ink-muted hover:bg-raised hover:text-ink"
      >
        Sign out
      </button>
    </div>
  );
}

/** Where this API runs, from the API itself: never assumed by the page. */
function EnvironmentBanner() {
  const env = useApi(getEnvironment);
  if (env.state !== "ready")
    return <p className="text-sm text-ink-muted">&nbsp;</p>;
  const { environment, deployed, region } = env.data;
  return (
    <p className="text-sm text-ink-muted">
      {deployed ? (
        <>
          <span className="font-medium text-ink">
            AWS {environment} environment
          </span>
          {region ? ` (${region})` : ""}. Real AWS resources; data is synthetic.
        </>
      ) : (
        "Local development environment. No AWS resources are connected."
      )}
    </p>
  );
}

/** The glow moves a little from tab to tab, so tabs sharing a pattern still differ. */
const GLOW_X = ["85%", "70%", "92%", "60%"];
const GLOW_Y = ["8%", "20%", "35%"];

export function Layout() {
  const backdrop = backdropFor(useLocation().pathname);
  const backdropStyle = backdrop
    ? ({
        "--glow-x": GLOW_X[backdrop.index % GLOW_X.length],
        "--glow-y": GLOW_Y[backdrop.index % GLOW_Y.length],
      } as CSSProperties)
    : undefined;
  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-10 focus:rounded focus:bg-accent focus:px-3 focus:py-2 focus:text-canvas"
      >
        Skip to content
      </a>

      <aside className="border-line bg-surface md:sticky md:top-0 md:h-screen md:w-60 md:shrink-0 md:border-r">
        <div className="flex items-center gap-2 border-b border-line px-4 py-4">
          <img src="/favicon.svg" alt="" className="size-6" />
          <span className="text-base font-semibold tracking-tight">
            SentinelEdge
          </span>
        </div>
        <nav
          aria-label="Primary"
          className="overflow-y-auto px-2 py-3 md:h-[calc(100vh-57px)]"
        >
          <ul className="flex gap-1 overflow-x-auto md:flex-col md:overflow-visible">
            {MODULES.map((m) => (
              <li key={m.path} className="shrink-0">
                <NavLink
                  to={m.path}
                  end={m.path === "/"}
                  className={({ isActive }) =>
                    `block rounded px-3 py-1.5 text-sm ${
                      isActive
                        ? "bg-raised text-ink shadow-[inset_2px_0_0_var(--color-accent)]"
                        : "text-ink-muted hover:bg-raised/60 hover:text-ink"
                    }`
                  }
                >
                  {m.label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-6 py-3">
          <EnvironmentBanner />
          <div className="flex items-center gap-5">
            <ApiStatus />
            <UserMenu />
          </div>
        </header>
        <main
          id="main"
          className="backdrop flex-1 px-6 py-6"
          data-backdrop={backdrop?.pattern}
          data-code={backdrop?.code}
          style={backdropStyle}
          tabIndex={-1}
        >
          <Outlet />
        </main>
      </div>
    </div>
  );
}
