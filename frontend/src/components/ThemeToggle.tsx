import { useState } from "react";
import { useAuth, useCurrentUser } from "../app/auth-context";

function SunIcon() {
  return (
    <svg aria-hidden="true" viewBox="0 0 20 20" className="size-4" fill="none" stroke="currentColor" strokeWidth="1.6">
      <circle cx="10" cy="10" r="3.5" />
      <path d="M10 1.5v2M10 16.5v2M1.5 10h2M16.5 10h2M4 4l1.4 1.4M14.6 14.6 16 16M4 16l1.4-1.4M14.6 5.4 16 4" strokeLinecap="round" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg aria-hidden="true" viewBox="0 0 20 20" className="size-4" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M16.5 12.2A7 7 0 0 1 7.8 3.5a7 7 0 1 0 8.7 8.7Z" strokeLinejoin="round" />
    </svg>
  );
}

/**
 * Light or dark theme for the signed-in user, beside their name on every page. The choice is
 * saved with their account, so it follows them to any device; nothing is kept in the browser.
 */
export function ThemeToggle() {
  const user = useCurrentUser();
  const { setTheme } = useAuth();
  const [failed, setFailed] = useState(false);
  const dark = user.theme === "dark";

  const toggle = () => {
    setFailed(false);
    setTheme(dark ? "light" : "dark").catch(() => setFailed(true));
  };

  return (
    <span className="flex items-center gap-2">
      <button
        type="button"
        role="switch"
        aria-checked={dark}
        aria-label="Dark theme"
        title={dark ? "Switch to the light theme" : "Switch to the dark theme"}
        onClick={toggle}
        className="inline-flex items-center gap-1.5 rounded border border-line px-2.5 py-1.5 text-ink-muted hover:bg-raised hover:text-ink"
      >
        {dark ? <MoonIcon /> : <SunIcon />}
        <span className="hidden sm:inline">{dark ? "Dark" : "Light"}</span>
      </button>
      {failed && (
        <span role="alert" className="text-xs text-fail">
          Theme not saved
        </span>
      )}
    </span>
  );
}
