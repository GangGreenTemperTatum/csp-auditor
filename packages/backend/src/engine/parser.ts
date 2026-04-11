import type { ParsedPolicy, PolicyDirective, PolicySource } from "shared";

import { createUniqueId } from "../utils";

const CSP_HEADER_NAMES = [
  "content-security-policy",
  "content-security-policy-report-only",
  "x-content-security-policy",
  "x-webkit-csp",
];

const DEPRECATED_HEADER_NAMES = ["x-content-security-policy", "x-webkit-csp"];

const KEYWORD_SOURCES = [
  "'self'",
  "'unsafe-inline'",
  "'unsafe-eval'",
  "'none'",
  "'strict-dynamic'",
  "'unsafe-hashes'",
  "'report-sample'",
  "'wasm-eval'",
  "'wasm-unsafe-eval'",
];

const INHERITING_DIRECTIVES = [
  "script-src",
  "style-src",
  "img-src",
  "font-src",
  "connect-src",
  "media-src",
  "object-src",
  "child-src",
  "frame-src",
  "worker-src",
  "manifest-src",
  "prefetch-src",
];

export function extractCspHeaders(
  headers: Record<string, string | string[]>,
): Array<{ name: string; value: string }> {
  const results: Array<{ name: string; value: string }> = [];

  for (const [headerName, headerValue] of Object.entries(headers)) {
    const normalized = headerName.toLowerCase();

    if (CSP_HEADER_NAMES.includes(normalized)) {
      const values = Array.isArray(headerValue) ? headerValue : [headerValue];

      for (const value of values) {
        if (typeof value === "string" && value.trim() !== "") {
          results.push({ name: normalized, value: value.trim() });
        }
      }
    }
  }

  return results;
}

export function parsePolicyHeader(
  headerName: string,
  headerValue: string,
  requestId: string,
  url?: string,
): ParsedPolicy {
  const policy: ParsedPolicy = {
    id: createUniqueId(),
    requestId,
    headerName,
    headerValue,
    directives: new Map(),
    isReportOnly: headerName.toLowerCase().includes("report-only"),
    isDeprecated: DEPRECATED_HEADER_NAMES.includes(headerName.toLowerCase()),
    parsedAt: new Date(),
    url,
  };

  const rawDirectives = headerValue
    .split(";")
    .map((d) => d.trim())
    .filter((d) => d !== "");

  for (const raw of rawDirectives) {
    const parts = raw.split(/\s+/).filter((p) => p !== "");
    if (parts.length === 0) continue;

    const name = parts[0]?.toLowerCase();
    if (name === undefined || name.trim() === "") continue;

    const values = parts.slice(1);
    const directive: PolicyDirective = {
      name,
      values,
      isImplicit: false,
      sources: values.map(classifySource),
    };

    policy.directives.set(name, directive);
  }

  applyDefaultSrcFallbacks(policy);
  return policy;
}

function classifySource(value: string): PolicySource {
  const trimmed = value.trim();

  if (KEYWORD_SOURCES.includes(trimmed)) {
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

function applyDefaultSrcFallbacks(policy: ParsedPolicy): void {
  const defaultSrc = policy.directives.get("default-src");
  if (defaultSrc === undefined) return;

  for (const name of INHERITING_DIRECTIVES) {
    if (!policy.directives.has(name)) {
      policy.directives.set(name, {
        name,
        values: [...defaultSrc.values],
        isImplicit: true,
        sources: [...defaultSrc.sources],
      });
    }
  }
}

export function hasUnsafeInline(directive: PolicyDirective): boolean {
  return directive.sources.some(
    (s) => s.kind === "keyword" && s.value === "'unsafe-inline'",
  );
}

export function hasWildcard(directive: PolicyDirective): boolean {
  return directive.sources.some((s) => s.isWildcard);
}

export function getHostSources(directive: PolicyDirective): PolicySource[] {
  return directive.sources.filter((s) => s.kind === "host");
}

export function isScriptRelatedDirective(name: string): boolean {
  return [
    "script-src",
    "object-src",
    "script-src-elem",
    "script-src-attr",
  ].includes(name);
}

export function isStyleRelatedDirective(name: string): boolean {
  return ["style-src", "style-src-elem", "style-src-attr"].includes(name);
}
