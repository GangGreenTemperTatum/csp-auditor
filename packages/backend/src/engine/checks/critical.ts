import type { ParsedPolicy, PolicyDirective, PolicyFinding } from "shared";

import { emitFinding, isCheckEnabled } from "../../utils/findings";
import {
  hasUnsafeInline,
  hasWildcard,
  isScriptRelatedDirective,
  isStyleRelatedDirective,
} from "../parser";

type ValueCheck = {
  match: string;
  checkId:
    | "script-wildcard"
    | "script-unsafe-inline"
    | "script-unsafe-eval"
    | "script-data-uri";
};

const SCRIPT_VALUE_CHECKS: ValueCheck[] = [
  { match: "*", checkId: "script-wildcard" },
  { match: "'unsafe-inline'", checkId: "script-unsafe-inline" },
  { match: "'unsafe-eval'", checkId: "script-unsafe-eval" },
  { match: "data:", checkId: "script-data-uri" },
];

export function runCriticalChecks(
  policy: ParsedPolicy,
  enabledChecks?: Record<string, boolean>,
): PolicyFinding[] {
  const findings: PolicyFinding[] = [];

  for (const [, directive] of policy.directives) {
    if (isScriptRelatedDirective(directive.name)) {
      findings.push(
        ...checkScriptValues(policy.requestId, directive, enabledChecks),
      );
    }

    if (isStyleRelatedDirective(directive.name)) {
      findings.push(
        ...checkStyleValues(policy.requestId, directive, enabledChecks),
      );
    }

    if (directive.name === "object-src") {
      for (const value of directive.values) {
        if (
          (value === "*" || value === "data:") &&
          isCheckEnabled("object-wildcard", enabledChecks)
        ) {
          findings.push(
            emitFinding(
              "object-wildcard",
              directive.name,
              value,
              policy.requestId,
            ),
          );
        }
      }
    }
  }

  return findings;
}

function checkScriptValues(
  requestId: string,
  directive: PolicyDirective,
  enabledChecks?: Record<string, boolean>,
): PolicyFinding[] {
  const findings: PolicyFinding[] = [];

  for (const value of directive.values) {
    for (const check of SCRIPT_VALUE_CHECKS) {
      if (
        value === check.match &&
        isCheckEnabled(check.checkId, enabledChecks)
      ) {
        findings.push(
          emitFinding(check.checkId, directive.name, value, requestId),
        );
      }
    }
  }

  return findings;
}

function checkStyleValues(
  requestId: string,
  directive: PolicyDirective,
  enabledChecks?: Record<string, boolean>,
): PolicyFinding[] {
  const findings: PolicyFinding[] = [];

  if (
    hasWildcard(directive) &&
    isCheckEnabled("style-wildcard", enabledChecks)
  ) {
    const wildcardValues = directive.sources
      .filter((s) => s.isWildcard)
      .map((s) => s.value)
      .join(", ");
    findings.push(
      emitFinding("style-wildcard", directive.name, wildcardValues, requestId),
    );
  }

  if (
    hasUnsafeInline(directive) &&
    isCheckEnabled("style-unsafe-inline", enabledChecks)
  ) {
    findings.push(
      emitFinding(
        "style-unsafe-inline",
        directive.name,
        "'unsafe-inline'",
        requestId,
      ),
    );
  }

  return findings;
}
