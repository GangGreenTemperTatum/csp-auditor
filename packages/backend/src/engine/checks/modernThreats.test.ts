import { buildPolicy } from "../policyBuilder";

import { runModernThreatChecks } from "./modernThreats";

describe("runModernThreatChecks", () => {
  it("detects AI/ML host", () => {
    const policy = buildPolicy({ "connect-src": ["api.openai.com"] });
    const findings = runModernThreatChecks(policy);
    expect(findings.some((f) => f.checkId === "ai-ml-host")).toBe(true);
  });

  it("detects Web3 host", () => {
    const policy = buildPolicy({ "script-src": ["metamask.io"] });
    const findings = runModernThreatChecks(policy);
    expect(findings.some((f) => f.checkId === "web3-host")).toBe(true);
  });

  it("detects CDN supply chain host", () => {
    const policy = buildPolicy({ "script-src": ["polyfill.io"] });
    const findings = runModernThreatChecks(policy);
    expect(findings.some((f) => f.checkId === "cdn-supply-chain")).toBe(true);
  });

  it("checks all directives not just script-src", () => {
    const policy = buildPolicy({
      "connect-src": ["huggingface.co"],
      "img-src": ["'self'"],
    });
    const findings = runModernThreatChecks(policy);
    expect(
      findings.some(
        (f) => f.checkId === "ai-ml-host" && f.directive === "connect-src",
      ),
    ).toBe(true);
  });

  it("returns empty for clean policy", () => {
    const policy = buildPolicy({
      "script-src": ["'self'"],
      "connect-src": ["'self'"],
    });
    const findings = runModernThreatChecks(policy);
    expect(findings).toHaveLength(0);
  });

  it("respects enabledChecks filter", () => {
    const policy = buildPolicy({ "script-src": ["polyfill.io"] });
    const findings = runModernThreatChecks(policy, {
      "cdn-supply-chain": false,
    });
    expect(findings).toHaveLength(0);
  });
});
