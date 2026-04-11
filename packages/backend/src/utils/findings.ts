import type { CheckId, PolicyFinding } from "shared";
import { CHECK_REGISTRY } from "shared";

import { createUniqueId } from "../utils";

export function emitFinding(
  checkId: CheckId,
  directive: string,
  value: string,
  requestId: string,
  descriptionOverride?: string,
): PolicyFinding {
  const def = CHECK_REGISTRY[checkId];
  return {
    id: createUniqueId(),
    checkId,
    severity: def.severity,
    directive,
    value,
    description: descriptionOverride ?? def.description,
    remediation: def.remediation,
    cweId: def.cweId,
    requestId,
  };
}

export function isCheckEnabled(
  checkId: string,
  enabledChecks?: Record<string, boolean>,
): boolean {
  return enabledChecks === undefined || (enabledChecks[checkId] ?? true);
}
