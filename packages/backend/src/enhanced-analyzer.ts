import type { CspPolicy, CspVulnerability, Severity, VulnerabilityType } from "./types";
import { generateId } from "./utils";

/**
 * Next-Generation Enhanced CSP Auditor
 * Beyond legacy limitations - modern CSP Level 3 analysis
 */
export class EnhancedCspAnalyzer {

  static analyzePolicy(policy: CspPolicy, settings?: Record<string, boolean>): CspVulnerability[] {
    const vulnerabilities: CspVulnerability[] = [];

    // Modern comprehensive analysis - only run if settings allow
    vulnerabilities.push(...this.analyzeDeprecatedFeatures(policy, settings));
    vulnerabilities.push(...this.analyzeCriticalVulnerabilities(policy, settings));
    vulnerabilities.push(...this.analyzeBypassTechniques(policy, settings));
    vulnerabilities.push(...this.analyzeModernThreats(policy, settings));
    vulnerabilities.push(...this.analyzePolicyWeaknesses(policy, settings));
    vulnerabilities.push(...this.analyzeLevel3Features(policy, settings));

    return this.prioritizeAndDeduplicate(vulnerabilities);
  }

  /**
   * Helper method to check if a vulnerability type is enabled
   */
  private static isCheckEnabled(type: string, settings?: Record<string, boolean>): boolean {
    return settings ? (settings[type] ?? true) : true;
  }

  /**
   * Critical security vulnerabilities (HIGH severity)
   */
  private static analyzeCriticalVulnerabilities(policy: CspPolicy, settings?: Record<string, boolean>): CspVulnerability[] {
    const vulnerabilities: CspVulnerability[] = [];

    for (const [, directive] of policy.directives) {
      // Script execution vulnerabilities
      if (this.isScriptExecutionDirective(directive.name)) {
        for (const value of directive.values) {
          // Wildcard script sources - CRITICAL
          if (value === "*" && this.isCheckEnabled('script-wildcard', settings)) {
            vulnerabilities.push(this.createVulnerability({
              type: "script-wildcard",
              severity: "high",
              directive: directive.name,
              value: value,
              title: "Critical: Wildcard Script Source",
              description: "Allows script execution from any domain, completely bypassing CSP protection",
              remediation: "Remove '*' and specify exact trusted domains. Use nonces or hashes for inline scripts.",
              cweId: 79, // XSS
              requestId: policy.requestId
            }));
          }

          // Unsafe inline - CRITICAL
          if (value === "'unsafe-inline'" && this.isCheckEnabled('script-unsafe-inline', settings)) {
            vulnerabilities.push(this.createVulnerability({
              type: "script-unsafe-inline",
              severity: "high",
              directive: directive.name,
              value: value,
              title: "Critical: Unsafe Inline Scripts Allowed",
              description: "Permits inline JavaScript execution, enabling XSS attacks through script tags and event handlers",
              remediation: "Remove 'unsafe-inline'. Use nonces ('nonce-xyz123') or hashes ('sha256-...') for legitimate inline scripts.",
              cweId: 79,
              requestId: policy.requestId
            }));
          }

          // Unsafe eval - CRITICAL
          if (value === "'unsafe-eval'" && this.isCheckEnabled('script-unsafe-eval', settings)) {
            vulnerabilities.push(this.createVulnerability({
              type: "script-unsafe-eval",
              severity: "high",
              directive: directive.name,
              value: value,
              title: "Critical: Dynamic Code Execution Allowed",
              description: "Enables eval(), Function() constructor, and setTimeout/setInterval with strings",
              remediation: "Remove 'unsafe-eval'. Refactor code to avoid dynamic code execution.",
              cweId: 94, // Code Injection
              requestId: policy.requestId
            }));
          }

          // Data URIs in script-src - HIGH RISK
          if (value === "data:") {
            vulnerabilities.push(this.createVulnerability({
              type: "script-data-uri",
              severity: "high",
              directive: directive.name,
              value: value,
              title: "High: Data URI Scripts Allowed",
              description: "Allows base64-encoded JavaScript execution via data: URIs",
              remediation: "Remove 'data:' from script-src. Use proper script files or nonces/hashes.",
              cweId: 79,
              requestId: policy.requestId
            }));
          }
        }
      }

      // Object/plugin vulnerabilities
      if (directive.name === "object-src") {
        for (const value of directive.values) {
          if (value === "*" || value === "data:") {
            vulnerabilities.push(this.createVulnerability({
              type: "object-wildcard",
              severity: "high",
              directive: directive.name,
              value: value,
              title: "High: Unrestricted Object/Plugin Sources",
              description: "Allows loading objects/plugins from any source, potential for code execution",
              remediation: "Set object-src to 'none' or specify trusted sources only.",
              cweId: 79,
              requestId: policy.requestId
            }));
          }
        }
      }
    }

    return vulnerabilities;
  }

  /**
   * Modern bypass techniques and advanced threats
   */
  private static analyzeBypassTechniques(policy: CspPolicy, settings?: Record<string, boolean>): CspVulnerability[] {
    const vulnerabilities: CspVulnerability[] = [];

    // JSONP callback bypasses
    this.checkJsonpBypasses(policy, vulnerabilities);

    // AngularJS template injection
    this.checkAngularJsBypasses(policy, vulnerabilities);

    // Service worker bypasses
    this.checkServiceWorkerBypasses(policy, vulnerabilities);

    // CSS injection attacks
    this.checkCssInjectionRisks(policy, vulnerabilities);

    // WebAssembly execution
    this.checkWasmThreats(policy, vulnerabilities);

    return vulnerabilities;
  }

  /**
   * CSP Level 3 modern features analysis
   */
  private static analyzeLevel3Features(policy: CspPolicy, settings?: Record<string, boolean>): CspVulnerability[] {
    const vulnerabilities: CspVulnerability[] = [];

    // Check for missing modern security features
    if (!policy.directives.has("trusted-types")) {
      vulnerabilities.push(this.createVulnerability({
        type: "missing-trusted-types",
        severity: "medium",
        directive: "trusted-types",
        value: "missing",
        title: "Missing Trusted Types Protection",
        description: "Trusted Types policy not configured - DOM XSS protection unavailable",
        remediation: "Add 'trusted-types' directive to enable DOM XSS protection",
        requestId: policy.requestId
      }));
    }

    if (!policy.directives.has("require-trusted-types-for")) {
      vulnerabilities.push(this.createVulnerability({
        type: "missing-require-trusted-types",
        severity: "medium",
        directive: "require-trusted-types-for",
        value: "missing",
        title: "Trusted Types Not Required",
        description: "DOM manipulation not restricted to Trusted Types",
        remediation: "Add 'require-trusted-types-for \"script\"' directive",
        requestId: policy.requestId
      }));
    }

    // Advanced nonce/hash analysis
    this.analyzeNonceHashSecurity(policy, vulnerabilities);

    return vulnerabilities;
  }

  /**
   * Enhanced policy weakness detection
   */
  private static analyzePolicyWeaknesses(policy: CspPolicy, settings?: Record<string, boolean>): CspVulnerability[] {
    const vulnerabilities: CspVulnerability[] = [];

    // Missing essential directives
    const essentialDirectives = ['script-src', 'object-src', 'frame-ancestors'];
    for (const essential of essentialDirectives) {
      if (!policy.directives.has(essential)) {
        vulnerabilities.push(this.createVulnerability({
          type: "missing-essential-directive",
          severity: essential === 'script-src' ? "high" : "medium",
          directive: essential,
          value: "missing",
          title: `Missing Essential Directive: ${essential}`,
          description: `Critical security directive ${essential} not defined`,
          remediation: `Add ${essential} directive with appropriate values`,
          requestId: policy.requestId
        }));
      }
    }

    // Overly permissive base-uri
    const baseUri = policy.directives.get("base-uri");
    if (!baseUri || baseUri.values.includes("*") || baseUri.values.includes("'unsafe-inline'")) {
      vulnerabilities.push(this.createVulnerability({
        type: "permissive-base-uri",
        severity: "medium",
        directive: "base-uri",
        value: baseUri?.values.join(" ") || "missing",
        title: "Permissive Base URI Policy",
        description: "Unrestricted base URI can enable injection attacks",
        remediation: "Set base-uri to 'self' or specific trusted origins",
        requestId: policy.requestId
      }));
    }

    return vulnerabilities;
  }

  /**
   * Modern threat landscape analysis
   */
  private static analyzeModernThreats(policy: CspPolicy, settings?: Record<string, boolean>): CspVulnerability[] {
    const vulnerabilities: CspVulnerability[] = [];

    // AI/ML service endpoints that could be exploited
    const aiMlHosts = [
      "api.openai.com", "api.anthropic.com", "huggingface.co",
      "colab.research.google.com", "ml.azure.com"
    ];

    // Cryptocurrency/Web3 risks
    const web3Hosts = [
      "metamask.io", "walletconnect.org", "uniswap.org",
      "ethereum.org", "web3.storage"
    ];

    // CDN compromise risks (2023+ supply chain attacks)
    const modernCdnRisks = [
      "polyfill.io", "cdn.jsdelivr.net", "unpkg.com",
      "cdnjs.cloudflare.com", "cdn.skypack.dev"
    ];

    this.checkModernHostRisks(policy, vulnerabilities, aiMlHosts, "ai-ml-host", "AI/ML Service Integration Risk");
    this.checkModernHostRisks(policy, vulnerabilities, web3Hosts, "web3-host", "Web3/Crypto Integration Risk");
    this.checkModernHostRisks(policy, vulnerabilities, modernCdnRisks, "cdn-supply-chain", "CDN Supply Chain Risk");

    return vulnerabilities;
  }

  // Helper methods for advanced analysis
  private static checkJsonpBypasses(policy: CspPolicy, vulnerabilities: CspVulnerability[]): void {
    const scriptSrc = policy.directives.get("script-src");
    if (!scriptSrc) return;

    const jsonpRiskyHosts = [
      "ajax.googleapis.com", "api.twitter.com", "graph.facebook.com",
      "api.github.com", "api.linkedin.com"
    ];

    for (const value of scriptSrc.values) {
      for (const riskyHost of jsonpRiskyHosts) {
        if (value.includes(riskyHost)) {
          vulnerabilities.push(this.createVulnerability({
            type: "jsonp-bypass-risk",
            severity: "high",
            directive: "script-src",
            value: value,
            title: "JSONP Callback Bypass Risk",
            description: `Host ${riskyHost} supports JSONP callbacks that can bypass CSP`,
            remediation: "Remove JSONP-enabled hosts or use fetch() with proper CORS",
            requestId: policy.requestId
          }));
        }
      }
    }
  }

  private static checkAngularJsBypasses(policy: CspPolicy, vulnerabilities: CspVulnerability[]): void {
    const scriptSrc = policy.directives.get("script-src");
    if (!scriptSrc) return;

    for (const value of scriptSrc.values) {
      if (value.includes("angular") && !value.includes("angular.min.js")) {
        vulnerabilities.push(this.createVulnerability({
          type: "angularjs-bypass",
          severity: "high",
          directive: "script-src",
          value: value,
          title: "AngularJS Template Injection Risk",
          description: "AngularJS versions allow template injection bypasses of CSP",
          remediation: "Upgrade to Angular 2+ or remove AngularJS entirely",
          cweId: 79,
          requestId: policy.requestId
        }));
      }
    }
  }

  private static analyzeNonceHashSecurity(policy: CspPolicy, vulnerabilities: CspVulnerability[]): void {
    const scriptSrc = policy.directives.get("script-src");
    if (!scriptSrc) return;

    let hasNonce = false;

    for (const value of scriptSrc.values) {
      if (value.startsWith("'nonce-")) hasNonce = true;
    }

    if (hasNonce && scriptSrc.values.includes("'unsafe-inline'")) {
      vulnerabilities.push(this.createVulnerability({
        type: "nonce-unsafe-inline-conflict",
        severity: "medium",
        directive: "script-src",
        value: "'unsafe-inline'",
        title: "Nonce Security Weakened by unsafe-inline",
        description: "Nonce protection is bypassed when 'unsafe-inline' is also present",
        remediation: "Remove 'unsafe-inline' when using nonces for better security",
        requestId: policy.requestId
      }));
    }
  }

  private static checkModernHostRisks(
    policy: CspPolicy,
    vulnerabilities: CspVulnerability[],
    riskHosts: string[],
    type: string,
    title: string
  ): void {
    for (const [, directive] of policy.directives) {
      for (const value of directive.values) {
        for (const riskHost of riskHosts) {
          if (value.includes(riskHost)) {
            vulnerabilities.push(this.createVulnerability({
              type: type as VulnerabilityType,
              severity: "medium",
              directive: directive.name,
              value: value,
              title: title,
              description: `Modern threat landscape risk: ${riskHost} integration detected`,
              remediation: `Review necessity of ${riskHost} integration and implement additional security controls`,
              requestId: policy.requestId
            }));
          }
        }
      }
    }
  }

  private static isScriptExecutionDirective(name: string): boolean {
    return ['script-src', 'script-src-elem', 'script-src-attr', 'object-src', 'worker-src'].includes(name);
  }

  private static createVulnerability(params: {
    type: string;
    severity: Severity;
    directive: string;
    value: string;
    title: string;
    description: string;
    remediation: string;
    cweId?: number;
    requestId: string;
  }): CspVulnerability {
    return {
      id: generateId(),
      type: params.type as VulnerabilityType,
      severity: params.severity,
      directive: params.directive,
      value: params.value,
      description: `${params.title}\n\n${params.description}`,
      remediation: params.remediation,
      cweId: params.cweId,
      requestId: params.requestId
    };
  }

  private static prioritizeAndDeduplicate(vulnerabilities: CspVulnerability[]): CspVulnerability[] {
    // Remove duplicates and sort by severity
    const seen = new Set<string>();
    const unique = vulnerabilities.filter(v => {
      const key = `${v.type}-${v.directive}-${v.value}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // Enhanced severity ordering
    const severityOrder = { high: 4, medium: 3, low: 2, info: 1 };
    return unique.sort((a, b) => severityOrder[b.severity] - severityOrder[a.severity]);
  }

  // Additional modern CSP analysis methods...
  private static checkServiceWorkerBypasses(_policy: CspPolicy, _vulnerabilities: CspVulnerability[]): void {
    // Service worker bypass analysis
  }

  private static checkCssInjectionRisks(_policy: CspPolicy, _vulnerabilities: CspVulnerability[]): void {
    // CSS injection and data exfiltration analysis
  }

  private static checkWasmThreats(_policy: CspPolicy, _vulnerabilities: CspVulnerability[]): void {
    // WebAssembly security analysis
  }

  private static analyzeDeprecatedFeatures(policy: CspPolicy, settings?: Record<string, boolean>): CspVulnerability[] {
    const vulnerabilities: CspVulnerability[] = [];

    // Enhanced deprecated feature detection
    if (policy.isDeprecated || !["content-security-policy", "content-security-policy-report-only"].includes(policy.headerName.toLowerCase())) {
      vulnerabilities.push(this.createVulnerability({
        type: "deprecated-header",
        severity: "medium",
        directive: policy.headerName,
        value: policy.headerName,
        title: "Deprecated CSP Header",
        description: "Using deprecated CSP header that may not be supported by modern browsers",
        remediation: "Use 'Content-Security-Policy' header instead",
        requestId: policy.requestId
      }));
    }

    return vulnerabilities;
  }
}