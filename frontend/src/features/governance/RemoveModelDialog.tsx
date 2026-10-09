import { useEffect, useId, useRef } from "react";
import { Button } from "../../components/forms";

interface Props {
  reference: string;
  name: string;
  canArchive: boolean;
  canDelete: boolean;
  busy: boolean;
  onArchive: () => void;
  onDelete: () => void;
  onCancel: () => void;
}

/**
 * What "Delete" offers for a threat model: archive (kept, marked out of use; leads and the
 * application's developers) or delete permanently (leads only). The server decides who may do
 * which and sends it as permissions; this dialog only shows what it was told.
 *
 * Same safety as ConfirmDialog: focus starts on Cancel, Escape and a click outside cancel, Tab
 * stays inside, and focus returns to the opener when it closes.
 */
export function RemoveModelDialog({ reference, name, canArchive, canDelete, busy, onArchive, onDelete, onCancel }: Props) {
  const titleId = useId();
  const bodyId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    cancelRef.current?.focus();
    return () => opener?.focus();
  }, []);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape" && !busy) {
        event.preventDefault();
        onCancel();
      } else if (event.key === "Tab") {
        const buttons = [...(dialogRef.current?.querySelectorAll<HTMLButtonElement>("button:not(:disabled)") ?? [])];
        if (!buttons.length) return;
        event.preventDefault();
        const at = buttons.indexOf(document.activeElement as HTMLButtonElement);
        const next = (at + (event.shiftKey ? -1 : 1) + buttons.length) % buttons.length;
        buttons[next]?.focus();
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
        className="w-full max-w-lg rounded-md border border-fail/50 bg-surface p-5 shadow-xl"
      >
        <h2 id={titleId} className="text-base font-semibold text-ink">
          Remove {reference}?
        </h2>
        <div id={bodyId} className="mt-3 space-y-3 text-sm text-ink-muted">
          <p>
            <strong className="break-words text-ink">{name}</strong>
          </p>
          {canArchive && (
            <p>
              <span className="font-medium text-ink">Archive</span> keeps the model, its threats and its history, and marks it out
              of use. Nothing is lost.
            </p>
          )}
          {canDelete && (
            <p>
              <span className="font-medium text-fail">Delete permanently</span> removes the model, its elements and its threats.
              It cannot be undone; the audit log keeps a summary of what was deleted.
            </p>
          )}
        </div>
        <div className="mt-5 flex flex-wrap justify-end gap-2">
          <Button ref={cancelRef} variant="secondary" disabled={busy} onClick={onCancel}>
            Cancel
          </Button>
          {canArchive && (
            <Button variant="secondary" busy={busy} onClick={onArchive}>
              Archive
            </Button>
          )}
          {canDelete && (
            <Button variant="danger" busy={busy} onClick={onDelete}>
              Delete permanently
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
