import { buildPolicy } from "../policyBuilder";

import { runCriticalChecks } from "./critical";

describe("runCriticalChecks", () => {
  it("detects wildcard in script-src", () => {
    const policy = buildPolicy({ "script-src": ["*"] });
    const findings = runCriticalChecks(policy);
    expect(findings.some((f) => f.checkId === "script-wildcard")).toBe(true);
  });

  it("detects unsafe-inline in script-src", () => {
    const policy = buildPolicy({ "script-src": ["'unsafe-inline'"] });
    const findings = runCriticalChecks(policy);
    expect(findings.some((f) => f.checkId === "script-unsafe-inline")).toBe(
      true,
    );
  });

  it("detects unsafe-eval in script-src", () => {
    const policy = buildPolicy({ "script-src": ["'unsafe-eval'"] });
    const findings = runCriticalChecks(policy);
    expect(findings.some((f) => f.checkId === "script-unsafe-eval")).toBe(true);
  });

  it("detects data: URI in script-src", () => {
    const policy = buildPolicy({ "script-src": ["data:"] });
    const findings = runCriticalChecks(policy);
    expect(findings.some((f) => f.checkId === "script-data-uri")).toBe(true);
  });

  it("detects wildcard in object-src", () => {
    const policy = buildPolicy({ "object-src": ["*"] });
    const findings = runCriticalChecks(policy);
    expect(findings.some((f) => f.checkId === "object-wildcard")).toBe(true);
  });

  it("detects wildcard in style-src", () => {
    const policy = buildPolicy({ "style-src": ["*"] });
    const findings = runCriticalChecks(policy);
    expect(findings.some((f) => f.checkId === "style-wildcard")).toBe(true);
  });

  it("detects unsafe-inline in style-src", () => {
    const policy = buildPolicy({ "style-src": ["'unsafe-inline'"] });
    const findings = runCriticalChecks(policy);
    expect(findings.some((f) => f.checkId === "style-unsafe-inline")).toBe(
      true,
    );
  });

  it("returns empty for secure policy", () => {
    const policy = buildPolicy({
      "script-src": ["'self'"],
      "style-src": ["'self'"],
      "object-src": ["'none'"],
    });
    const findings = runCriticalChecks(policy);
    expect(findings).toHaveLength(0);
  });

  it("respects enabledChecks filter", () => {
    const policy = buildPolicy({ "script-src": ["*", "'unsafe-inline'"] });
    const findings = runCriticalChecks(policy, { "script-wildcard": false });
    expect(findings.some((f) => f.checkId === "script-wildcard")).toBe(false);
    expect(findings.some((f) => f.checkId === "script-unsafe-inline")).toBe(
      true,
    );
  });

  it("checks script-src-elem directive", () => {
    const policy = buildPolicy({ "script-src-elem": ["'unsafe-inline'"] });
    const findings = runCriticalChecks(policy);
    expect(findings.some((f) => f.checkId === "script-unsafe-inline")).toBe(
      true,
    );
  });
});
