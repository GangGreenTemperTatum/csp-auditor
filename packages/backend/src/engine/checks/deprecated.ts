import type { ParsedPolicy, PolicyFinding } from "shared";

import { emitFinding, isCheckEnabled } from "../../utils/findings";

const STANDARD_HEADER_NAMES = [
  "content-security-policy",
  "content-security-policy-report-only",
];

export function runDeprecatedChecks(
  policy: ParsedPolicy,
  enabledChecks?: Record<string, boolean>,
): PolicyFinding[] {
  if (!isCheckEnabled("deprecated-header", enabledChecks)) return [];

  if (
    policy.isDeprecated ||
    !STANDARD_HEADER_NAMES.includes(policy.headerName.toLowerCase())
  ) {
    return [
      emitFinding(
        "deprecated-header",
        policy.headerName,
        policy.headerName,
        policy.requestId,
      ),
    ];
  }

  return [];
}
