import type { ParsedPolicy, PolicyFinding } from "shared";

import {
  runBypassChecks,
  runCriticalChecks,
  runDeprecatedChecks,
  runHostSecurityChecks,
  runMissingDirectiveChecks,
  runModernThreatChecks,
  runTrustedTypesChecks,
} from "./checks";
import { deduplicateAndSort } from "./deduplicator";

export function analyzePolicy(
  policy: ParsedPolicy,
  enabledChecks?: Record<string, boolean>,
): PolicyFinding[] {
  const findings: PolicyFinding[] = [
    ...runDeprecatedChecks(policy, enabledChecks),
    ...runCriticalChecks(policy, enabledChecks),
    ...runBypassChecks(policy, enabledChecks),
    ...runModernThreatChecks(policy, enabledChecks),
    ...runHostSecurityChecks(policy, enabledChecks),
    ...runMissingDirectiveChecks(policy, enabledChecks),
    ...runTrustedTypesChecks(policy, enabledChecks),
  ];

  return deduplicateAndSort(findings);
}
