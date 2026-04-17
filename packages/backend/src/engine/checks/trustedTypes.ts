import type { ParsedPolicy, PolicyFinding } from "shared";

import { emitFinding, isCheckEnabled } from "../../utils/findings";

export function runTrustedTypesChecks(
  policy: ParsedPolicy,
  enabledChecks?: Record<string, boolean>,
): PolicyFinding[] {
  const findings: PolicyFinding[] = [];

  if (
    isCheckEnabled("missing-trusted-types", enabledChecks) &&
    !policy.directives.has("trusted-types")
  ) {
    findings.push(
      emitFinding(
        "missing-trusted-types",
        "trusted-types",
        "missing",
        policy.requestId,
      ),
    );
  }

  if (
    isCheckEnabled("missing-require-trusted-types", enabledChecks) &&
    !policy.directives.has("require-trusted-types-for")
  ) {
    findings.push(
      emitFinding(
        "missing-require-trusted-types",
        "require-trusted-types-for",
        "missing",
        policy.requestId,
      ),
    );
  }

  if (isCheckEnabled("nonce-unsafe-inline-conflict", enabledChecks)) {
    const scriptSrc = policy.directives.get("script-src");
    if (scriptSrc !== undefined) {
      const hasNonce = scriptSrc.values.some((v) => v.startsWith("'nonce-"));
      const hasInline = scriptSrc.values.includes("'unsafe-inline'");

      if (hasNonce && hasInline) {
        findings.push(
          emitFinding(
            "nonce-unsafe-inline-conflict",
            "script-src",
            "'unsafe-inline'",
            policy.requestId,
          ),
        );
      }
    }
  }

  return findings;
}
