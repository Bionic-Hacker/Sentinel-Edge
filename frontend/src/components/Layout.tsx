import { useState, type CSSProperties } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useAuth, useCurrentUser } from "../app/auth-context";
import { MODULES, NAV_GROUPS, NAV_LABEL, backdropFor, groupFor } from "../app/modules";
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

/**
 * The sidebar: parent titles that open and close when pressed. The group holding the current page
 * opens by itself unless the viewer closed it; closed groups keep their links out of the page.
 * Held in memory only (ADR-0003 keeps browser storage out of the SPA); the layout stays mounted
 * between pages, so the choices last the session.
 */
function SideNav() {
  const { pathname } = useLocation();
  const active = groupFor(pathname);
  const [toggled, setToggled] = useState<Record<string, boolean>>({});
  const byPath = new Map(MODULES.map((m) => [m.path, m]));

  function toggle(id: string, open: boolean) {
    setToggled((current) => ({ ...current, [id]: !open }));
  }

  return (
    <nav aria-label="Primary" className="overflow-y-auto px-2 py-3 md:h-[calc(100vh-57px)]">
      <ul className="space-y-1">
        {NAV_GROUPS.map((group) => {
          const holdsActive = active?.id === group.id;
          const open = toggled[group.id] ?? holdsActive;
          const listId = `nav-${group.id}`;
          return (
            <li key={group.id}>
              <button
                type="button"
                aria-expanded={open}
                aria-controls={listId}
                onClick={() => toggle(group.id, open)}
                className={`nav-group flex w-full items-center justify-between rounded px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider ${
                  holdsActive ? "text-ink" : "text-ink-muted hover:text-ink"
                } hover:bg-raised/60`}
              >
                <span className="flex items-center gap-2">
                  {holdsActive && !open && <span aria-hidden="true" className="size-1.5 rounded-full bg-accent" />}
                  {group.label}
                </span>
                <svg
                  aria-hidden="true"
                  viewBox="0 0 20 20"
                  className={`size-3.5 shrink-0 transition-transform ${open ? "rotate-90" : ""}`}
                >
                  <path d="M7 5l6 5-6 5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                </svg>
              </button>
              <ul id={listId} hidden={!open} className="mb-2 ml-3 mt-0.5 space-y-0.5 border-l border-line pl-2">
                {group.paths.map((path) => {
                  const m = byPath.get(path);
                  if (!m) return null;
                  return (
                    <li key={path}>
                      <NavLink
                        to={path}
                        end={path === "/"}
                        className={({ isActive }) =>
                          `block rounded px-3 py-1.5 text-sm ${
                            isActive
                              ? "bg-raised text-ink shadow-[inset_2px_0_0_var(--color-accent)]"
                              : "text-ink-muted hover:bg-raised/60 hover:text-ink"
                          }`
                        }
                      >
                        {NAV_LABEL[path] ?? m.label}
                      </NavLink>
                    </li>
                  );
                })}
              </ul>
            </li>
          );
        })}
      </ul>
    </nav>
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
        <SideNav />
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
