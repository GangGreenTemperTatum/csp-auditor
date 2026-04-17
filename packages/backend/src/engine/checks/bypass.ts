import type { ParsedPolicy, PolicyFinding } from "shared";

import { JSONP_CAPABLE_HOSTS } from "../../data";
import { stripDomainPrefix } from "../../utils";
import { emitFinding, isCheckEnabled } from "../../utils/findings";

export function runBypassChecks(
  policy: ParsedPolicy,
  enabledChecks?: Record<string, boolean>,
): PolicyFinding[] {
  const findings: PolicyFinding[] = [];
  const scriptSrc = policy.directives.get("script-src");
  if (scriptSrc === undefined) return findings;

  for (const value of scriptSrc.values) {
    if (isCheckEnabled("jsonp-bypass-risk", enabledChecks)) {
      const normalized = stripDomainPrefix(value);
      for (const host of JSONP_CAPABLE_HOSTS) {
        if (normalized === host || normalized.endsWith(`.${host}`)) {
          findings.push(
            emitFinding(
              "jsonp-bypass-risk",
              "script-src",
              value,
              policy.requestId,
              `Host ${host} supports JSONP callbacks that can bypass CSP`,
            ),
          );
        }
      }
    }

    if (isCheckEnabled("angularjs-bypass", enabledChecks)) {
      if (value.includes("angular") && !value.includes("angular.min.js")) {
        findings.push(
          emitFinding(
            "angularjs-bypass",
            "script-src",
            value,
            policy.requestId,
          ),
        );
      }
    }
  }

  return findings;
}
