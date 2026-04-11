import type { PolicyFinding } from "shared";

import { deduplicateAndSort } from "./deduplicator";

function fakeFinding(overrides: Partial<PolicyFinding>): PolicyFinding {
  return {
    id: "f-1",
    checkId: "script-wildcard",
    severity: "high",
    directive: "script-src",
    value: "*",
    description: "test",
    remediation: "fix it",
    requestId: "req-1",
    ...overrides,
  };
}

describe("deduplicateAndSort", () => {
  it("removes duplicate findings with same checkId+directive+value", () => {
    const findings = [fakeFinding({ id: "f-1" }), fakeFinding({ id: "f-2" })];
    const result = deduplicateAndSort(findings);
    expect(result).toHaveLength(1);
  });

  it("preserves findings with different keys", () => {
    const findings = [
      fakeFinding({
        checkId: "script-wildcard",
        directive: "script-src",
        value: "*",
      }),
      fakeFinding({
        checkId: "script-unsafe-inline",
        directive: "script-src",
        value: "'unsafe-inline'",
      }),
    ];
    const result = deduplicateAndSort(findings);
    expect(result).toHaveLength(2);
  });

  it("sorts by severity descending", () => {
    const findings = [
      fakeFinding({ severity: "low", checkId: "style-wildcard" }),
      fakeFinding({ severity: "high", checkId: "script-wildcard" }),
      fakeFinding({
        severity: "medium",
        checkId: "deprecated-header",
        directive: "header",
        value: "x",
      }),
    ];
    const result = deduplicateAndSort(findings);
    expect(result[0]!.severity).toBe("high");
    expect(result[1]!.severity).toBe("medium");
    expect(result[2]!.severity).toBe("low");
  });

  it("handles empty array", () => {
    expect(deduplicateAndSort([])).toHaveLength(0);
  });
});
