import { describe, expect, it } from "vitest";
import { MODULES, backdropFor } from "./modules";

describe("tab backdrops", () => {
  it("gives every sidebar tab a pattern", () => {
    for (const m of MODULES)
      expect(backdropFor(m.path)?.pattern, m.label).toBeDefined();
  });

  it("gives every tab its own code", () => {
    const codes = MODULES.map((m) => backdropFor(m.path)?.code);
    expect(new Set(codes).size).toBe(MODULES.length);
  });

  it("matches a tab's sub-pages and nothing else", () => {
    expect(backdropFor("/incidents/12")?.code).toBe("INC-06");
    expect(backdropFor("/apis")?.pattern).toBe("circuit");
    expect(backdropFor("/waf")?.code).toBe("WAF-03");
    expect(backdropFor("/apisx")).toBeUndefined();
    expect(backdropFor("/login")).toBeUndefined();
  });
});
