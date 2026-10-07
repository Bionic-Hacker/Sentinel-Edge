import qrcode from "qrcode-generator";
import { useMemo } from "react";

/**
 * Renders a QR code as React-built SVG from the generator's module grid. The otpauth URI (which
 * contains the TOTP secret) never leaves the browser: no third-party QR service, no injected
 * markup, no data: URL.
 */
export function QrCode({ value, label, size = 192 }: { value: string; label: string; size?: number }) {
  const cells = useMemo(() => {
    const qr = qrcode(0, "M");
    qr.addData(value);
    qr.make();
    const count = qr.getModuleCount();
    const dark: [number, number][] = [];
    for (let row = 0; row < count; row += 1) {
      for (let col = 0; col < count; col += 1) if (qr.isDark(row, col)) dark.push([col, row]);
    }
    return { count, dark };
  }, [value]);

  const quiet = 2;
  const span = cells.count + quiet * 2;
  return (
    <svg
      role="img"
      aria-label={label}
      width={size}
      height={size}
      viewBox={`0 0 ${span} ${span}`}
      shapeRendering="crispEdges"
      className="rounded bg-white"
    >
      <rect width={span} height={span} fill="#ffffff" />
      {cells.dark.map(([x, y]) => (
        <rect key={`${x}-${y}`} x={x + quiet} y={y + quiet} width={1} height={1} fill="#000000" />
      ))}
    </svg>
  );
}
