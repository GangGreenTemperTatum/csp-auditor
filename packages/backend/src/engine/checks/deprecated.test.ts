import { buildPolicy } from "../policyBuilder";

import { runDeprecatedChecks } from "./deprecated";

describe("runDeprecatedChecks", () => {
  it("detects x-content-security-policy header", () => {
    const policy = buildPolicy(
      { "default-src": ["'self'"] },
      { headerName: "x-content-security-policy" },
    );
    const findings = runDeprecatedChecks(policy);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.checkId).toBe("deprecated-header");
  });

  it("detects x-webkit-csp header", () => {
    const policy = buildPolicy(
      { "default-src": ["'self'"] },
      { headerName: "x-webkit-csp" },
    );
    const findings = runDeprecatedChecks(policy);
    expect(findings).toHaveLength(1);
  });

  it("returns empty for standard CSP header", () => {
    const policy = buildPolicy(
      { "default-src": ["'self'"] },
      { headerName: "content-security-policy" },
    );
    const findings = runDeprecatedChecks(policy);
    expect(findings).toHaveLength(0);
  });
});
