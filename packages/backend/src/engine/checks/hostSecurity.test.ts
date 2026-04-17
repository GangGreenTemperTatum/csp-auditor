import { buildPolicy } from "../policyBuilder";

import { runHostSecurityChecks } from "./hostSecurity";

describe("runHostSecurityChecks", () => {
  it("detects user content host", () => {
    const policy = buildPolicy({ "script-src": ["test.github.io"] });
    const findings = runHostSecurityChecks(policy);
    expect(findings.some((f) => f.checkId === "user-content-host")).toBe(true);
  });

  it("detects vulnerable JS host without path", () => {
    const policy = buildPolicy({ "script-src": ["cdn.jsdelivr.net"] });
    const findings = runHostSecurityChecks(policy);
    expect(findings.some((f) => f.checkId === "vulnerable-js-host")).toBe(true);
  });

  it("detects wildcard in non-script directive", () => {
    const policy = buildPolicy({ "img-src": ["*"] });
    const findings = runHostSecurityChecks(policy);
    expect(findings.some((f) => f.checkId === "wildcard-limited")).toBe(true);
  });

  it("skips wildcard detection for script directives", () => {
    const policy = buildPolicy({ "script-src": ["*"] });
    const findings = runHostSecurityChecks(policy);
    expect(findings.some((f) => f.checkId === "wildcard-limited")).toBe(false);
  });

  it("skips wildcard detection for style directives", () => {
    const policy = buildPolicy({ "style-src": ["*"] });
    const findings = runHostSecurityChecks(policy);
    expect(findings.some((f) => f.checkId === "wildcard-limited")).toBe(false);
  });

  it("returns empty for clean policy", () => {
    const policy = buildPolicy({
      "script-src": ["'self'"],
      "img-src": ["'self'"],
    });
    const findings = runHostSecurityChecks(policy);
    expect(findings).toHaveLength(0);
  });

  it("respects enabledChecks filter", () => {
    const policy = buildPolicy({ "script-src": ["test.github.io"] });
    const findings = runHostSecurityChecks(policy, {
      "user-content-host": false,
    });
    expect(findings.some((f) => f.checkId === "user-content-host")).toBe(false);
  });
});
