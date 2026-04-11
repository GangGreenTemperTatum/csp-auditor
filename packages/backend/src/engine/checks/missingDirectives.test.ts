import { buildPolicy } from "../policyBuilder";

import { runMissingDirectiveChecks } from "./missingDirectives";

describe("runMissingDirectiveChecks", () => {
  it("detects missing script-src", () => {
    const policy = buildPolicy({ "style-src": ["'self'"] });
    const findings = runMissingDirectiveChecks(policy);
    expect(findings.some((f) => f.directive === "script-src")).toBe(true);
  });

  it("detects missing object-src and frame-ancestors", () => {
    const policy = buildPolicy({ "script-src": ["'self'"] });
    const findings = runMissingDirectiveChecks(policy);
    expect(findings.some((f) => f.directive === "object-src")).toBe(true);
    expect(findings.some((f) => f.directive === "frame-ancestors")).toBe(true);
  });

  it("detects permissive base-uri with wildcard", () => {
    const policy = buildPolicy({ "base-uri": ["*"] });
    const findings = runMissingDirectiveChecks(policy);
    expect(findings.some((f) => f.checkId === "permissive-base-uri")).toBe(
      true,
    );
  });

  it("detects missing base-uri", () => {
    const policy = buildPolicy({ "script-src": ["'self'"] });
    const findings = runMissingDirectiveChecks(policy);
    expect(findings.some((f) => f.checkId === "permissive-base-uri")).toBe(
      true,
    );
  });

  it("returns empty when all essential directives present", () => {
    const policy = buildPolicy({
      "script-src": ["'self'"],
      "object-src": ["'none'"],
      "frame-ancestors": ["'self'"],
      "base-uri": ["'self'"],
    });
    const findings = runMissingDirectiveChecks(policy);
    expect(findings).toHaveLength(0);
  });
});
