import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

// The session module is a singleton: start every test signed out.
import { endSession } from "../lib/auth/session";
afterEach(() => endSession());
