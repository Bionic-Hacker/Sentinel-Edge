import { NavLink, Outlet } from "react-router-dom";
import { useAuth, useCurrentUser } from "../app/auth-context";
import { MODULES } from "../app/modules";
import { ApiStatus } from "./ApiStatus";

function UserMenu() {
  const user = useCurrentUser();
  const { logout } = useAuth();
  return (
    <div className="flex items-center gap-3 text-sm">
      <span className="text-right leading-tight">
        <span className="block text-ink">{user.display_name}</span>
        <span className="block text-xs text-ink-muted">{user.role.replace("_", " ").toLowerCase()}</span>
      </span>
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

export function Layout() {
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
          <span className="text-base font-semibold tracking-tight">SentinelEdge</span>
        </div>
        <nav aria-label="Primary" className="overflow-y-auto px-2 py-3 md:h-[calc(100vh-57px)]">
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
          <p className="text-sm text-ink-muted">
            Local development environment. No AWS resources are connected.
          </p>
          <div className="flex items-center gap-5">
            <ApiStatus />
            <UserMenu />
          </div>
        </header>
        <main id="main" className="flex-1 px-6 py-6" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
