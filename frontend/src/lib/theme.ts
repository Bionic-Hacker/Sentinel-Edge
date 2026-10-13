import type { Theme } from "./types";

/**
 * Apply a colour theme to the page. The themes are two sets of design tokens (index.css): light
 * is the default, and `data-theme="dark"` on the root element switches to the dark one. The
 * choice itself is saved with the user's account, not in browser storage (ADR-0003).
 */
export function applyTheme(theme: Theme): void {
  const root = document.documentElement;
  if (theme === "dark") root.dataset.theme = "dark";
  else delete root.dataset.theme;
}

export function currentTheme(): Theme {
  return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
}
