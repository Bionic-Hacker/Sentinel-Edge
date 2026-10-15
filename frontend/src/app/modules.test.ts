import { describe, expect, it } from "vitest";
import { MODULES, backdropFor } from "./modules";

describe("tab backdrops", () => {
  it("gives every sidebar tab a pattern", () => {
    for (const m of MODULES)
      expect(backdropFor(m.path)?.pattern, m.label).toBeDefined();
  });

  it("matches a tab's sub-pages and nothing else", () => {
    expect(backdropFor("/incidents/12")?.pattern).toBe("radar");
    expect(backdropFor("/apis")?.pattern).toBe("circuit");
    expect(backdropFor("/apisx")).toBeUndefined();
    expect(backdropFor("/login")).toBeUndefined();
  });
});
