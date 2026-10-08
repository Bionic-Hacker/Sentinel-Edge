import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";
import { endSession } from "../lib/auth/session";

// One hook, in this order. Vitest may run separate afterEach hooks in reverse: ending the session
// while the app is still mounted updates AuthProvider outside act() (a warning on every test).
afterEach(() => {
  cleanup(); // unmount first
  endSession(); // the session module is a singleton: start every test signed out
  vi.restoreAllMocks();
});
