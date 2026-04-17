import type { ParsedPolicy, PolicyFinding } from "shared";

import {
  isUserContentHost,
  isVulnerableJsHost,
  stripDomainPrefix,
} from "../../utils";
import { emitFinding, isCheckEnabled } from "../../utils/findings";
import {
  getHostSources,
  hasWildcard,
  isScriptRelatedDirective,
  isStyleRelatedDirective,
} from "../parser";

export function runHostSecurityChecks(
  policy: ParsedPolicy,
  enabledChecks?: Record<string, boolean>,
): PolicyFinding[] {
  const findings: PolicyFinding[] = [];

  for (const [, directive] of policy.directives) {
    for (const source of getHostSources(directive)) {
      const domain = stripDomainPrefix(source.value);

      if (
        isCheckEnabled("user-content-host", enabledChecks) &&
        isUserContentHost(domain)
      ) {
        findings.push(
          emitFinding(
            "user-content-host",
            directive.name,
            source.value,
            policy.requestId,
          ),
        );
      }

      const vulnResult = isVulnerableJsHost(domain);
      if (
        isCheckEnabled("vulnerable-js-host", enabledChecks) &&
        vulnResult.isVulnerable
      ) {
        findings.push(
          emitFinding(
            "vulnerable-js-host",
            directive.name,
            source.value,
            policy.requestId,
            vulnResult.risk,
          ),
        );
      }
    }

    if (
      isCheckEnabled("wildcard-limited", enabledChecks) &&
      hasWildcard(directive) &&
      !isScriptRelatedDirective(directive.name) &&
      !isStyleRelatedDirective(directive.name)
    ) {
      findings.push(
        emitFinding("wildcard-limited", directive.name, "*", policy.requestId),
      );
    }
  }

  return findings;
}
