/**
 * Small, dependency-free charts drawn as SVG.
 *
 * Geometry lives in SVG attributes, never in inline styles, so the strict Content-Security-Policy
 * (no 'unsafe-inline') holds. Each chart has a readout that follows the pointer, a keyboard
 * equivalent (the plot is a slider over its columns: arrow keys, Home, End), and a table twin,
 * so no value is reachable only by hovering.
 */
import { useEffect, useRef, useState, type KeyboardEvent, type PointerEvent } from "react";

export interface ColumnPoint {
  key: string;
  /** Short x-axis label, shown on a subset of columns. */
  label: string;
  value: number;
  /** Full description for the readout and the table, e.g. "18:00 UTC: 12 events, 2 high". */
  readout: string;
}

// The plot is drawn in CSS pixels at the container's measured width, so axis text keeps its real
// size on a phone instead of shrinking with a scaled-down drawing. VIEW_W is the width used until
// the first measurement (and in tests, where there is no layout).
const VIEW_W = 640;
const MIN_LABEL_GAP = 44;
const PLOT_H = 128;
const AXIS_W = 34;
const BAR_MAX = 12;

function niceMax(value: number): number {
  if (value <= 4) return 4;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * magnitude).find((s) => s * 4 >= value) ?? value;
  return step * 4;
}

/** A column with a 4px rounded data end and a square baseline. */
function columnPath(x: number, w: number, top: number, base: number): string {
  const h = base - top;
  if (h <= 0) return "";
  const r = Math.min(4, w / 2, h);
  return `M${x},${base}V${top + r}Q${x},${top} ${x + r},${top}H${x + w - r}Q${x + w},${top} ${x + w},${top + r}V${base}Z`;
}

export function ColumnChart({
  title,
  points,
  labelEvery = 6,
  emptyText = "Nothing recorded in this window.",
}: {
  title: string;
  points: ColumnPoint[];
  labelEvery?: number;
  emptyText?: string;
}) {
  const [active, setActive] = useState<number | null>(null);
  const [measured, setMeasured] = useState<number | null>(null);
  const frame = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const element = frame.current;
    if (!element || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(([entry]) => {
      const w = Math.round(entry?.contentRect.width ?? 0);
      if (w > 0) setMeasured(w);
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  const max = niceMax(Math.max(0, ...points.map((p) => p.value)));
  const width = measured ?? VIEW_W;
  const height = PLOT_H + 18;
  const band = (width - AXIS_W) / Math.max(points.length, 1);
  // Fewer x labels when columns are narrow: keep labelEvery's rhythm but never crowd the text.
  const every = labelEvery * Math.max(1, Math.ceil(MIN_LABEL_GAP / (band * labelEvery)));
  // Thin columns with at least a 2-unit gap between neighbours.
  const barW = Math.max(1, Math.min(BAR_MAX, band * 0.7, band - 2));
  const ticks = [0, max / 2, max];
  const y = (v: number) => PLOT_H - (v / max) * (PLOT_H - 6);
  const total = points.reduce((sum, p) => sum + p.value, 0);
  const shown = active !== null ? points[active] : undefined;
  const last = points.length - 1;
  const current = active ?? last;

  function onPointerMove(event: PointerEvent<SVGSVGElement>) {
    const rect = event.currentTarget.getBoundingClientRect();
    if (rect.width === 0) return;
    const x = ((event.clientX - rect.left) / rect.width) * width - AXIS_W;
    const index = Math.floor(x / band);
    setActive(index >= 0 && index < points.length ? index : null);
  }

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const moves: Record<string, number> = {
      ArrowLeft: Math.max(0, current - 1),
      ArrowDown: Math.max(0, current - 1),
      ArrowRight: Math.min(last, current + 1),
      ArrowUp: Math.min(last, current + 1),
      Home: 0,
      End: last,
    };
    const next = moves[event.key];
    if (next !== undefined) {
      event.preventDefault();
      setActive(next);
    }
  }

  const plot = (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      width={width}
      height={height}
      className="block max-w-full"
      onPointerMove={onPointerMove}
      onPointerLeave={() => setActive(null)}
      aria-hidden="true"
    >
      {ticks.map((t) => (
        <g key={t}>
          <line x1={AXIS_W} x2={width} y1={y(t)} y2={y(t)} className="stroke-line" strokeWidth={1} vectorEffect="non-scaling-stroke" />
          <text x={AXIS_W - 6} y={y(t) + 3} textAnchor="end" className="fill-ink-muted text-[11px]">
            {Math.round(t).toLocaleString()}
          </text>
        </g>
      ))}
      {points.map((p, i) => {
        const x = AXIS_W + i * band + (band - barW) / 2;
        return (
          <g key={p.key}>
            {active === i && <rect x={AXIS_W + i * band} y={0} width={band} height={PLOT_H} className="fill-raised" />}
            <path d={columnPath(x, barW, y(p.value), PLOT_H)} className={active === i ? "fill-ink" : "fill-accent"} />
            {i % every === 0 && (
              <text x={AXIS_W + i * band + band / 2} y={PLOT_H + 15} textAnchor="middle" className="fill-ink-muted text-[11px]">
                {p.label}
              </text>
            )}
          </g>
        );
      })}
    </svg>
  );

  return (
    <figure className="space-y-2">
      <figcaption className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="text-sm font-medium">{title}</span>
        <span className="text-xs text-ink-muted">
          {shown ? shown.readout : total ? "Point at a column, or focus the chart and use the arrow keys." : emptyText}
        </span>
      </figcaption>
      <div ref={frame}>
      {points.length ? (
        // A slider over the columns: screen readers announce each column's readout as the value.
        <div
          role="slider"
          tabIndex={0}
          aria-label={title}
          aria-valuemin={0}
          aria-valuemax={last}
          aria-valuenow={current}
          aria-valuetext={points[current]?.readout ?? emptyText}
          onKeyDown={onKeyDown}
          onFocus={() => setActive((a) => a ?? last)}
          onBlur={() => setActive(null)}
          className="rounded focus-visible:outline-2 focus-visible:outline-accent"
        >
          {plot}
        </div>
      ) : (
        <div role="img" aria-label={`${title}: ${emptyText}`}>
          {plot}
        </div>
      )}
      </div>
      <details className="text-xs text-ink-muted">
        <summary className="cursor-pointer select-none hover:text-ink">Show as table</summary>
        <table className="mt-2 w-full text-left">
          <caption className="sr-only">{title}</caption>
          <tbody className="divide-y divide-line">
            {points.map((p) => (
              <tr key={p.key}>
                <td className="py-1 tabular-nums">{p.readout}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </figure>
  );
}

export interface BarItem {
  key: string;
  label: string;
  value: number;
  hint?: string;
}

/** Ranked horizontal bars, one hue; the value sits at the bar's tip in text colour. */
export function BarList({ items, label, empty = "None in this window." }: { items: BarItem[]; label: string; empty?: string }) {
  if (!items.length) return <p className="text-sm text-ink-muted">{empty}</p>;
  const max = Math.max(...items.map((i) => i.value), 1);
  return (
    <ul aria-label={label} className="space-y-2">
      {items.map((item) => (
        <li key={item.key} title={item.hint}>
          <div className="flex items-baseline justify-between gap-3 text-sm">
            <span className="truncate">{item.label}</span>
            <span className="tabular-nums text-ink-muted">{item.value.toLocaleString()}</span>
          </div>
          {/* Unscaled SVG with percentage widths (attributes, not styles: the CSP forbids inline
              styles), so the rounded ends stay round at any width instead of stretching. */}
          <svg className="mt-1 block h-1.5 w-full" aria-hidden="true">
            <rect x={0} y={0} width="100%" height="100%" rx={3} className="fill-raised" />
            <rect
              x={0}
              y={0}
              width={`${Math.max(1, (item.value / max) * 100).toFixed(2)}%`}
              height="100%"
              rx={3}
              className="fill-accent"
            />
          </svg>
        </li>
      ))}
    </ul>
  );
}
