import type { ParsedPolicy, PolicyDirective, PolicySource } from "shared";

import { createUniqueId } from "../utils";

function classifySource(value: string): PolicySource {
  const trimmed = value.trim();

  if (
    [
      "'self'",
      "'unsafe-inline'",
      "'unsafe-eval'",
      "'none'",
      "'strict-dynamic'",
    ].includes(trimmed)
  ) {
    return {
      value: trimmed,
      kind: "keyword",
      isWildcard: false,
      isUnsafe: trimmed.includes("unsafe"),
    };
  }
  if (trimmed.startsWith("'nonce-") && trimmed.endsWith("'")) {
    return {
      value: trimmed,
      kind: "nonce",
      isWildcard: false,
      isUnsafe: false,
    };
  }
  if (/^'sha(256|384|512)-[A-Za-z0-9+/=]+'$/.test(trimmed)) {
    return { value: trimmed, kind: "hash", isWildcard: false, isUnsafe: false };
  }
  if (trimmed.endsWith(":") && !trimmed.includes("//")) {
    return {
      value: trimmed,
      kind: "scheme",
      isWildcard: trimmed === "*",
      isUnsafe: false,
    };
  }
  return {
    value: trimmed,
    kind: "host",
    isWildcard: trimmed === "*" || trimmed.startsWith("*"),
    isUnsafe: false,
  };
}

export function buildPolicy(
  directives: Record<string, string[]>,
  options?: { headerName?: string; requestId?: string; url?: string },
): ParsedPolicy {
  const headerName = options?.headerName ?? "content-security-policy";
  const requestId = options?.requestId ?? "test-request-1";
  const directiveMap = new Map<string, PolicyDirective>();

  for (const [name, values] of Object.entries(directives)) {
    directiveMap.set(name, {
      name,
      values,
      isImplicit: false,
      sources: values.map(classifySource),
    });
  }

  return {
    id: createUniqueId(),
    requestId,
    headerName,
    headerValue: Object.entries(directives)
      .map(([k, v]) => `${k} ${v.join(" ")}`)
      .join("; "),
    directives: directiveMap,
    isReportOnly: headerName.includes("report-only"),
    isDeprecated: ["x-content-security-policy", "x-webkit-csp"].includes(
      headerName,
    ),
    parsedAt: new Date(),
    url: options?.url,
  };
}
