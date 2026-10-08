import { act, render, type RenderResult } from "@testing-library/react";
import type { ReactElement } from "react";
import { onSessionChange } from "../lib/auth/session";

const SETTLE_TIMEOUT_MS = 2000;

/**
 * Render the app and wait, inside act(), until the initial silent sign-in has finished.
 *
 * React runs effects only when an act() scope exits, so the wait happens in two steps:
 * render() (which wraps its own act) runs the AuthProvider's mount effect, starting the silent
 * sign-in; a second, async act() then waits for its outcome, so the provider's state update
 * lands inside act. Waiting inside the same act() as render would deadlock until the timeout:
 * the effect that starts the sign-in would not have run yet. Both outcomes notify:
 * startSession on success, endSession on 401.
 */
export async function renderSettled(ui: ReactElement): Promise<RenderResult> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let unsubscribe: () => void = () => undefined;
  const settled = new Promise<void>((resolve) => {
    unsubscribe = onSessionChange(() => resolve());
    timer = setTimeout(resolve, SETTLE_TIMEOUT_MS); // safety net: never hang a test
  });
  const view = render(ui);
  await act(async () => {
    await settled;
  });
  // The provider's own update can land a tick after the notification (on a slower or busier
  // machine, after the scope above has closed): flush one more macrotask inside act().
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
  unsubscribe();
  clearTimeout(timer);
  return view;
}
