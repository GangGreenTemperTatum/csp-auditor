import { buildPolicy } from "../policyBuilder";

import { runBypassChecks } from "./bypass";

describe("runBypassChecks", () => {
  it("detects JSONP-capable host", () => {
    const policy = buildPolicy({ "script-src": ["ajax.googleapis.com"] });
    const findings = runBypassChecks(policy);
    expect(findings.some((f) => f.checkId === "jsonp-bypass-risk")).toBe(true);
  });

  it("detects multiple JSONP hosts", () => {
    const policy = buildPolicy({
      "script-src": ["ajax.googleapis.com", "api.twitter.com"],
    });
    const findings = runBypassChecks(policy);
    expect(
      findings.filter((f) => f.checkId === "jsonp-bypass-risk").length,
    ).toBe(2);
  });

  it("detects AngularJS pattern", () => {
    const policy = buildPolicy({
      "script-src": [
        "cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.js",
      ],
    });
    const findings = runBypassChecks(policy);
    expect(findings.some((f) => f.checkId === "angularjs-bypass")).toBe(true);
  });

  it("ignores angular.min.js", () => {
    const policy = buildPolicy({
      "script-src": ["cdnjs.cloudflare.com/ajax/libs/angular.min.js"],
    });
    const findings = runBypassChecks(policy);
    expect(findings.some((f) => f.checkId === "angularjs-bypass")).toBe(false);
  });

  it("returns empty when no script-src", () => {
    const policy = buildPolicy({ "default-src": ["'self'"] });
    const findings = runBypassChecks(policy);
    expect(findings).toHaveLength(0);
  });

  it("respects enabledChecks filter", () => {
    const policy = buildPolicy({ "script-src": ["ajax.googleapis.com"] });
    const findings = runBypassChecks(policy, { "jsonp-bypass-risk": false });
    expect(findings).toHaveLength(0);
  });
});
