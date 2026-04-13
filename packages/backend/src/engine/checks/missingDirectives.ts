import type { ParsedPolicy, PolicyFinding } from "shared";

import { emitFinding, isCheckEnabled } from "../../utils/findings";

const ESSENTIAL_DIRECTIVES = ["script-src", "object-src", "frame-ancestors"];

export function runMissingDirectiveChecks(
  policy: ParsedPolicy,
  enabledChecks?: Record<string, boolean>,
): PolicyFinding[] {
  const findings: PolicyFinding[] = [];

  if (isCheckEnabled("missing-essential-directive", enabledChecks)) {
    for (const name of ESSENTIAL_DIRECTIVES) {
      if (!policy.directives.has(name)) {
        findings.push(
          emitFinding(
            "missing-essential-directive",
            name,
            "missing",
            policy.requestId,
            `Critical security directive ${name} not defined`,
          ),
        );
      }
    }
  }

  if (isCheckEnabled("permissive-base-uri", enabledChecks)) {
    const baseUri = policy.directives.get("base-uri");
    if (
      baseUri === undefined ||
      baseUri.values.some((v) => v.includes("*")) ||
      baseUri.values.includes("'unsafe-inline'")
    ) {
      findings.push(
        emitFinding(
          "permissive-base-uri",
          "base-uri",
          baseUri?.values.join(" ") ?? "missing",
          policy.requestId,
        ),
      );
    }
  }

  return findings;
}
