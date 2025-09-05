import { BlacklistManager } from "./blacklists";
import { CspParser } from "./csp-parser";
import type { CspDirective, CspPolicy, CspVulnerability } from "./types";
import { extractDomain, generateId } from "./utils";
import { VULNERABILITY_RULES } from "./vulnerability-rules";

export class SecurityAnalyzer {
  static analyzePolicy(policy: CspPolicy): CspVulnerability[] {
    const vulnerabilities: CspVulnerability[] = [];

    // Check for deprecated header
    if (policy.isDeprecated) {
      vulnerabilities.push(
        this.createVulnerability(
          "deprecated-header",
          policy.headerName,
          policy.headerName,
          policy.requestId,
        ),
      );
    }

    // Analyze each directive
    for (const [, directive] of policy.directives) {
      vulnerabilities.push(
        ...this.analyzeDirective(directive, policy.requestId),
      );
    }

    return this.deduplicateVulnerabilities(vulnerabilities);
  }

  private static analyzeDirective(
    directive: CspDirective,
    requestId: string,
  ): CspVulnerability[] {
    const vulnerabilities: CspVulnerability[] = [];

    // Check script-related directives
    if (CspParser.isScriptDirective(directive.name)) {
      vulnerabilities.push(...this.checkScriptSources(directive, requestId));
    }

    // Check style-related directives
    if (CspParser.isStyleDirective(directive.name)) {
      vulnerabilities.push(...this.checkStyleSources(directive, requestId));
    }

    // Check for blacklisted hosts in any directive
    vulnerabilities.push(...this.checkBlacklistedHosts(directive, requestId));

    // Check for general wildcard usage (low severity)
    if (
      CspParser.hasWildcard(directive) &&
      !CspParser.isScriptDirective(directive.name) &&
      !CspParser.isStyleDirective(directive.name)
    ) {
      vulnerabilities.push(
        this.createVulnerability(
          "wildcard-limited",
          directive.name,
          "*",
          requestId,
        ),
      );
    }

    return vulnerabilities;
  }

  private static checkScriptSources(
    directive: CspDirective,
    requestId: string,
  ): CspVulnerability[] {
    const vulnerabilities: CspVulnerability[] = [];

    // Check for wildcard in script sources
    if (CspParser.hasWildcard(directive)) {
      vulnerabilities.push(
        this.createVulnerability(
          "script-wildcard",
          directive.name,
          this.getWildcardValues(directive),
          requestId,
        ),
      );
    }

    // Check for unsafe-inline
    if (CspParser.hasUnsafeInline(directive)) {
      vulnerabilities.push(
        this.createVulnerability(
          "script-unsafe-inline",
          directive.name,
          "'unsafe-inline'",
          requestId,
        ),
      );
    }

    // Check for unsafe-eval
    if (CspParser.hasUnsafeEval(directive)) {
      vulnerabilities.push(
        this.createVulnerability(
          "script-unsafe-eval",
          directive.name,
          "'unsafe-eval'",
          requestId,
        ),
      );
    }

    return vulnerabilities;
  }

  private static checkStyleSources(
    directive: CspDirective,
    requestId: string,
  ): CspVulnerability[] {
    const vulnerabilities: CspVulnerability[] = [];

    // Check for wildcard in style sources
    if (CspParser.hasWildcard(directive)) {
      vulnerabilities.push(
        this.createVulnerability(
          "style-wildcard",
          directive.name,
          this.getWildcardValues(directive),
          requestId,
        ),
      );
    }

    // Check for unsafe-inline in styles
    if (CspParser.hasUnsafeInline(directive)) {
      vulnerabilities.push(
        this.createVulnerability(
          "style-unsafe-inline",
          directive.name,
          "'unsafe-inline'",
          requestId,
        ),
      );
    }

    return vulnerabilities;
  }

  private static checkBlacklistedHosts(
    directive: CspDirective,
    requestId: string,
  ): CspVulnerability[] {
    const vulnerabilities: CspVulnerability[] = [];
    const hostSources = CspParser.getHostSources(directive);

    for (const source of hostSources) {
      const domain = extractDomain(source.value);
      const domainIssues = BlacklistManager.checkDomainVariants(domain);

      for (const issue of domainIssues) {
        if (issue.type === "user-content") {
          vulnerabilities.push(
            this.createVulnerability(
              "user-content-host",
              directive.name,
              source.value,
              requestId,
            ),
          );
        } else if (issue.type === "vulnerable-js") {
          vulnerabilities.push(
            this.createVulnerability(
              "vulnerable-js-host",
              directive.name,
              source.value,
              requestId,
            ),
          );
        }
      }
    }

    return vulnerabilities;
  }

  private static getWildcardValues(directive: CspDirective): string {
    return directive.sources
      .filter((source) => source.isWildcard)
      .map((source) => source.value)
      .join(", ");
  }

  private static createVulnerability(
    type: CspVulnerability["type"],
    directive: string,
    value: string,
    requestId: string,
  ): CspVulnerability {
    const rule = VULNERABILITY_RULES[type];

    return {
      id: generateId(),
      type,
      severity: rule.severity,
      directive,
      value,
      description: rule.description,
      remediation: rule.remediation,
      cweId: rule.cweId,
      requestId,
    };
  }

  private static deduplicateVulnerabilities(
    vulnerabilities: CspVulnerability[],
  ): CspVulnerability[] {
    const seen = new Set<string>();
    const deduplicated: CspVulnerability[] = [];

    for (const vuln of vulnerabilities) {
      const key = `${vuln.type}-${vuln.directive}-${vuln.value}`;
      if (!seen.has(key)) {
        seen.add(key);
        deduplicated.push(vuln);
      }
    }

    return deduplicated;
  }

  static getSeverityOrder(severity: CspVulnerability["severity"]): number {
    const order = { high: 3, medium: 2, low: 1, info: 0 };
    return order[severity];
  }

  static sortVulnerabilitiesBySeverity(
    vulnerabilities: CspVulnerability[],
  ): CspVulnerability[] {
    return [...vulnerabilities].sort(
      (a, b) =>
        this.getSeverityOrder(b.severity) - this.getSeverityOrder(a.severity),
    );
  }

  static getVulnerabilityStats(
    vulnerabilities: CspVulnerability[],
  ): Record<string, number> {
    const stats = { high: 0, medium: 0, low: 0, info: 0, total: 0 };

    for (const vuln of vulnerabilities) {
      stats[vuln.severity]++;
      stats.total++;
    }

    return stats;
  }
}
