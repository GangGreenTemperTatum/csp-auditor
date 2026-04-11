import { buildPolicy } from "../policyBuilder";

import { runTrustedTypesChecks } from "./trustedTypes";

describe("runTrustedTypesChecks", () => {
  it("detects missing trusted-types", () => {
    const policy = buildPolicy({ "script-src": ["'self'"] });
    const findings = runTrustedTypesChecks(policy);
    expect(findings.some((f) => f.checkId === "missing-trusted-types")).toBe(
      true,
    );
  });

  it("detects missing require-trusted-types-for", () => {
    const policy = buildPolicy({ "script-src": ["'self'"] });
    const findings = runTrustedTypesChecks(policy);
    expect(
      findings.some((f) => f.checkId === "missing-require-trusted-types"),
    ).toBe(true);
  });

  it("detects nonce + unsafe-inline conflict", () => {
    const policy = buildPolicy({
      "script-src": ["'nonce-abc123'", "'unsafe-inline'"],
    });
    const findings = runTrustedTypesChecks(policy);
    expect(
      findings.some((f) => f.checkId === "nonce-unsafe-inline-conflict"),
    ).toBe(true);
  });

  it("does not flag trusted-types when directives are configured", () => {
    const policy = buildPolicy({
      "trusted-types": ["default"],
      "require-trusted-types-for": ["'script'"],
      "script-src": ["'self'"],
    });
    const findings = runTrustedTypesChecks(policy);
    expect(findings.some((f) => f.checkId === "missing-trusted-types")).toBe(
      false,
    );
    expect(
      findings.some((f) => f.checkId === "missing-require-trusted-types"),
    ).toBe(false);
  });

  it("does not flag nonce conflict when unsafe-inline is absent", () => {
    const policy = buildPolicy({ "script-src": ["'nonce-abc123'"] });
    const findings = runTrustedTypesChecks(policy);
    expect(
      findings.some((f) => f.checkId === "nonce-unsafe-inline-conflict"),
    ).toBe(false);
  });
});
