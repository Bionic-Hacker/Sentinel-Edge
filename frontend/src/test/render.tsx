import { act, render, type RenderResult } from "@testing-library/react";
import type { ReactElement } from "react";
import { onSessionChange } from "../lib/auth/session";

const SETTLE_TIMEOUT_MS = 2000;

/**
 * Render the app and wait, inside act(), until the initial silent sign-in has finished.
 *
 * The AuthProvider's first refresh resolves at a time that depends on the runtime (Web Locks
 * availability, how the response body is read). Waiting for the session-change notification
 * itself, rather than for a fixed number of ticks, keeps every state update inside act() on
 * any Node.js version. Both outcomes notify: startSession on success, endSession on 401.
 */
export async function renderSettled(ui: ReactElement): Promise<RenderResult> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const settled = new Promise<void>((resolve) => {
    const unsubscribe = onSessionChange(() => {
      unsubscribe();
      resolve();
    });
    timer = setTimeout(() => {
      unsubscribe();
      resolve(); // safety net: never hang a test
    }, SETTLE_TIMEOUT_MS);
  });
  let view!: RenderResult;
  await act(async () => {
    view = render(ui);
    await settled;
  });
  clearTimeout(timer);
  return view;
}
