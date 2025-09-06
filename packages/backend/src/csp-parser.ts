import type { CspDirective, CspPolicy, CspSource } from "./types";
import { generateId } from "./utils";

export class CspParser {
  private static readonly CSP_HEADERS = [
    "content-security-policy",
    "content-security-policy-report-only",
    "x-content-security-policy",
    "x-webkit-csp",
  ];

  private static readonly DEPRECATED_HEADERS = [
    "x-content-security-policy",
    "x-webkit-csp",
  ];

  private static readonly KEYWORD_SOURCES = [
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

  static extractCspHeaders(
    headers: Record<string, string | string[]>,
  ): Array<{ name: string; value: string }> {
    const cspHeaders: Array<{ name: string; value: string }> = [];

    for (const [headerName, headerValue] of Object.entries(headers)) {
      const normalizedName = headerName.toLowerCase();

      if (this.CSP_HEADERS.includes(normalizedName)) {
        const values = Array.isArray(headerValue) ? headerValue : [headerValue];

        for (const value of values) {
          if (value && typeof value === "string") {
            cspHeaders.push({ name: normalizedName, value: value.trim() });
          }
        }
      }
    }

    return cspHeaders;
  }

  static parsePolicy(
    headerName: string,
    headerValue: string,
    requestId: string,
    url?: string,
  ): CspPolicy {
    const policy: CspPolicy = {
      id: generateId(),
      requestId,
      headerName,
      headerValue,
      directives: new Map(),
      isReportOnly: headerName.includes("report-only"),
      isDeprecated: this.DEPRECATED_HEADERS.includes(headerName),
      parsedAt: new Date(),
      url,
    };

    // Split the header value by semicolons to get individual directives
    const directiveStrings = headerValue
      .split(";")
      .map((d) => d.trim())
      .filter((d) => d);

    for (const directiveString of directiveStrings) {
      const parts = directiveString.split(/\s+/).filter((part) => part);
      if (parts.length === 0) continue;

      const directiveName = parts[0]?.toLowerCase();
      if (directiveName === undefined || directiveName.trim() === "") continue;
      const directiveValues = parts.slice(1);

      const directive: CspDirective = {
        name: directiveName,
        values: directiveValues,
        implicit: false,
        sources: this.parseSourceList(directiveValues),
      };

      policy.directives.set(directiveName, directive);
    }

    // Compute effective policy with default-src inheritance
    this.applyDefaultSrcInheritance(policy);

    return policy;
  }

  private static parseSourceList(values: string[]): CspSource[] {
    return values.map((value) => this.parseSource(value));
  }

  private static parseSource(value: string): CspSource {
    const trimmedValue = value.trim();

    // Check for keywords
    if (this.KEYWORD_SOURCES.includes(trimmedValue)) {
      return {
        value: trimmedValue,
        type: "keyword",
        isWildcard: false,
        isUnsafe: trimmedValue.includes("unsafe"),
      };
    }

    // Check for nonce
    if (trimmedValue.startsWith("'nonce-")) {
      return {
        value: trimmedValue,
        type: "nonce",
        isWildcard: false,
        isUnsafe: false,
      };
    }

    // Check for hash
    if (trimmedValue.startsWith("'sha") && trimmedValue.endsWith("'")) {
      return {
        value: trimmedValue,
        type: "hash",
        isWildcard: false,
        isUnsafe: false,
      };
    }

    // Check for scheme
    if (trimmedValue.includes(":") && !trimmedValue.includes("//")) {
      return {
        value: trimmedValue,
        type: "scheme",
        isWildcard: trimmedValue === "*",
        isUnsafe: false,
      };
    }

    // Default to host
    return {
      value: trimmedValue,
      type: "host",
      isWildcard: trimmedValue === "*" || trimmedValue.startsWith("*"),
      isUnsafe: false,
    };
  }

  private static applyDefaultSrcInheritance(policy: CspPolicy): void {
    const defaultSrcDirective = policy.directives.get("default-src");
    if (!defaultSrcDirective) return;

    // List of directives that inherit from default-src if not explicitly set
    const inheritingDirectives = [
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

    for (const directiveName of inheritingDirectives) {
      if (!policy.directives.has(directiveName)) {
        // Create implicit directive inheriting from default-src
        const implicitDirective: CspDirective = {
          name: directiveName,
          values: [...defaultSrcDirective.values],
          implicit: true,
          sources: [...defaultSrcDirective.sources],
        };

        policy.directives.set(directiveName, implicitDirective);
      }
    }
  }

  static computeEffectivePolicy(policies: CspPolicy[]): CspPolicy | undefined {
    if (policies.length === 0) return undefined;
    if (policies.length === 1) return policies[0] ?? undefined;

    // For multiple policies, we need to intersect the directives
    // This is a simplified approach - real CSP combination is complex
    const firstPolicy = policies[0];
    if (!firstPolicy) return undefined;

    const effectivePolicy = { ...firstPolicy };
    effectivePolicy.id = generateId();
    effectivePolicy.headerValue = policies.map((p) => p.headerValue).join("; ");

    return effectivePolicy;
  }

  static getDirectiveSourcesAsString(directive: CspDirective): string {
    return directive.values.join(" ");
  }

  static hasUnsafeInline(directive: CspDirective): boolean {
    return directive.sources.some(
      (source) =>
        source.type === "keyword" && source.value === "'unsafe-inline'",
    );
  }

  static hasUnsafeEval(directive: CspDirective): boolean {
    return directive.sources.some(
      (source) => source.type === "keyword" && source.value === "'unsafe-eval'",
    );
  }

  static hasWildcard(directive: CspDirective): boolean {
    return directive.sources.some((source) => source.isWildcard);
  }

  static getHostSources(directive: CspDirective): CspSource[] {
    return directive.sources.filter((source) => source.type === "host");
  }

  static isScriptDirective(directiveName: string): boolean {
    return [
      "script-src",
      "object-src",
      "script-src-elem",
      "script-src-attr",
    ].includes(directiveName);
  }

  static isStyleDirective(directiveName: string): boolean {
    return ["style-src", "style-src-elem", "style-src-attr"].includes(
      directiveName,
    );
  }
}
