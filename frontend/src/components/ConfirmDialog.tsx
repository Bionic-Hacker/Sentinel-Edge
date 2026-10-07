import { useEffect, useId, useRef, type ReactNode } from "react";
import { Button } from "./forms";

interface ConfirmDialogProps {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * Modal confirmation for destructive actions.
 *
 * Safe by default: focus starts on Cancel (Enter or Space cannot confirm by accident), Escape
 * and a click outside cancel, focus is kept inside the dialog, and it returns to whatever
 * opened the dialog when it closes.
 */
export function ConfirmDialog({ title, children, confirmLabel, busy = false, onConfirm, onCancel }: ConfirmDialogProps) {
  const titleId = useId();
  const bodyId = useId();
  const cancelRef = useRef<HTMLButtonElement>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    cancelRef.current?.focus();
    return () => opener?.focus();
  }, []);

  // Listeners on the document, not the dialog: they work wherever focus or the pointer is.
  const dialogRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape" && !busy) {
        event.preventDefault();
        onCancel();
      } else if (event.key === "Tab") {
        // Two focusable elements: Tab and Shift+Tab cycle between them and never leave.
        event.preventDefault();
        (document.activeElement === cancelRef.current ? confirmRef : cancelRef).current?.focus();
      }
    }
    function onPointerDown(event: PointerEvent) {
      if (!busy && event.target instanceof Node && !dialogRef.current?.contains(event.target)) onCancel();
    }
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("pointerdown", onPointerDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("pointerdown", onPointerDown);
    };
  }, [busy, onCancel]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-canvas/80 p-4">
      <div
        ref={dialogRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={bodyId}
        className="w-full max-w-md rounded-md border border-fail/50 bg-surface p-5 shadow-xl"
      >
        <h2 id={titleId} className="flex items-center gap-2 text-base font-semibold text-ink">
          <WarningIcon />
          {title}
        </h2>
        <div id={bodyId} className="mt-3 space-y-2 text-sm text-ink-muted">
          {children}
        </div>
        <div className="mt-5 flex justify-end gap-2">
          <Button ref={cancelRef} variant="secondary" disabled={busy} onClick={onCancel}>
            Cancel
          </Button>
          <Button ref={confirmRef} variant="danger" busy={busy} onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}

function WarningIcon() {
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" className="h-5 w-5 shrink-0 text-fail" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" />
      <path d="M12 9v4" />
      <path d="M12 17h.01" />
    </svg>
  );
}

export function TrashIcon() {
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 6h18" />
      <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
      <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
      <path d="M10 11v6" />
      <path d="M14 11v6" />
    </svg>
  );
}
