import type { ReactNode } from "react";

/**
 * The page kit: one header and one collapsible section, used by every tab so they read alike.
 * Long explanations live behind "About this page"; secondary blocks start collapsed.
 */

export function PageHeader({
  title,
  summary,
  about,
  actions,
}: {
  title: ReactNode;
  summary?: ReactNode;
  about?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
      <div className="min-w-0 max-w-3xl">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {summary && <p className="mt-1 text-ink-muted">{summary}</p>}
        {about && (
          <details className="about mt-2 text-sm">
            <summary className="inline-flex cursor-pointer items-center gap-1.5 rounded text-accent hover:underline">
              <Chevron />
              About this page
            </summary>
            <div className="mt-2 max-w-prose space-y-2 text-ink-muted">{about}</div>
          </details>
        )}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2 pt-1">{actions}</div>}
    </header>
  );
}

/**
 * A titled block that opens and closes. Native <details>, so it needs no script, keeps its content
 * in the page for search and screen readers, and opens with the keyboard.
 */
export function Section({
  title,
  count,
  meta,
  defaultOpen = true,
  children,
  id,
}: {
  title: ReactNode;
  count?: number | undefined;
  meta?: ReactNode;
  defaultOpen?: boolean;
  children: ReactNode;
  id?: string;
}) {
  // A labelled region, as the plain sections it replaces were, so landmarks still name it.
  const block = (
    <details open={defaultOpen} className="section-block rounded-md border border-line bg-surface">
      <summary className="flex cursor-pointer items-center gap-3 rounded-md px-4 py-3 hover:bg-raised/60">
        <Chevron />
        <h2 id={id} className="text-base font-semibold">
          {title}
        </h2>
        {count !== undefined && (
          <span className="rounded-full bg-raised px-2 py-0.5 text-xs tabular-nums text-ink-muted">{count}</span>
        )}
        {meta && <span className="min-w-0 truncate text-sm text-ink-muted">{meta}</span>}
      </summary>
      <div className="border-t border-line px-4 py-4">{children}</div>
    </details>
  );
  return id ? <section aria-labelledby={id}>{block}</section> : block;
}

function Chevron() {
  return (
    <svg aria-hidden="true" viewBox="0 0 20 20" className="chevron h-4 w-4 shrink-0 text-ink-muted transition-transform">
      <path d="M7 5l6 5-6 5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}
