import type { SDK } from "caido:plugin";

import type { CspVulnerability } from "./types";
import { VULNERABILITY_RULES } from "./vulnerability-rules";

export class FindingsGenerator {
  private static readonly REPORTER_NAME = "CSP Auditor";

  static async createFinding(
    vulnerability: CspVulnerability,
    request: any, // Caido Request object
    response: any, // Caido Response object
    sdk: SDK,
  ): Promise<void> {
    try {
      const rule = VULNERABILITY_RULES[vulnerability.type];

      const finding = {
        title: rule.title,
        description: this.generateDetailedDescription(vulnerability, rule),
        reporter: this.REPORTER_NAME,
        request: request,
        response: response,
        severity: this.mapSeverityToCaido(vulnerability.severity),
      };

      await sdk.findings.create(finding);
      sdk.console.log(
        `Created finding: ${rule.title} for ${vulnerability.directive}`,
      );
    } catch (error) {
      sdk.console.error(
        `Failed to create finding: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  static async createMultipleFindings(
    vulnerabilities: CspVulnerability[],
    request: any,
    response: any,
    sdk: SDK,
  ): Promise<void> {
    const promises = vulnerabilities.map((vuln) =>
      this.createFinding(vuln, request, response, sdk),
    );

    try {
      await Promise.all(promises);
      sdk.console.log(`Created ${vulnerabilities.length} CSP findings`);
    } catch (error) {
      sdk.console.error(
        `Failed to create some findings: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  private static generateDetailedDescription(
    vulnerability: CspVulnerability,
    rule: (typeof VULNERABILITY_RULES)[keyof typeof VULNERABILITY_RULES],
  ): string {
    const sections = [
      `<h3>Vulnerability Details</h3>`,
      `<p><strong>CSP Directive:</strong> ${vulnerability.directive}</p>`,
      `<p><strong>Vulnerable Value:</strong> <code>${vulnerability.value}</code></p>`,
      `<p><strong>Severity:</strong> ${vulnerability.severity.toUpperCase()}</p>`,

      `<h3>Description</h3>`,
      `<p>${rule.description}</p>`,

      `<h3>Remediation</h3>`,
      `<p>${rule.remediation}</p>`,
    ];

    // Add CWE information if available
    if (rule.cweId) {
      sections.push(
        `<h3>References</h3>`,
        `<p><strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/${rule.cweId}.html">CWE-${rule.cweId}</a></p>`,
      );
    }

    // Add specific guidance based on vulnerability type
    sections.push(this.getSpecificGuidance(vulnerability));

    return sections.join("\n");
  }

  private static getSpecificGuidance(vulnerability: CspVulnerability): string {
    switch (vulnerability.type) {
      case "script-unsafe-inline":
        return `
          <h3>Secure Alternatives</h3>
          <p>Instead of 'unsafe-inline', consider:</p>
          <ul>
            <li>Use nonces: <code>'nonce-randomValue123'</code></li>
            <li>Use hashes: <code>'sha256-base64HashValue'</code></li>
            <li>Move inline scripts to external files</li>
            <li>Use event listeners instead of inline event handlers</li>
          </ul>
        `;

      case "script-wildcard":
        return `
          <h3>Secure Configuration</h3>
          <p>Replace wildcard (*) with specific domains:</p>
          <ul>
            <li><code>'self'</code> - for same-origin scripts</li>
            <li><code>https://trusted-cdn.example.com</code> - for specific CDNs</li>
            <li>Use Subresource Integrity (SRI) for third-party scripts</li>
          </ul>
        `;

      case "user-content-host":
        return `
          <h3>Risk Mitigation</h3>
          <p>If you must use user content domains:</p>
          <ul>
            <li>Implement Subresource Integrity (SRI) checks</li>
            <li>Use specific paths instead of allowing entire domain</li>
            <li>Consider hosting resources on your own infrastructure</li>
            <li>Regularly audit allowed resources</li>
          </ul>
        `;

      case "vulnerable-js-host":
        return `
          <h3>Library Security</h3>
          <p>To address vulnerable JavaScript libraries:</p>
          <ul>
            <li>Update to the latest secure versions</li>
            <li>Use specific version URLs instead of latest/auto-updating links</li>
            <li>Consider self-hosting critical libraries</li>
            <li>Implement SRI to prevent tampering</li>
          </ul>
        `;

      case "deprecated-header":
        return `
          <h3>Header Migration</h3>
          <p>Update your CSP headers:</p>
          <ul>
            <li>Replace <code>X-Content-Security-Policy</code> with <code>Content-Security-Policy</code></li>
            <li>Replace <code>X-WebKit-CSP</code> with <code>Content-Security-Policy</code></li>
            <li>Test thoroughly with modern browsers</li>
          </ul>
        `;

      default:
        return `
          <h3>Additional Resources</h3>
          <p>For more information about CSP security:</p>
          <ul>
            <li><a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP">MDN CSP Documentation</a></li>
            <li><a href="https://csp-evaluator.withgoogle.com/">Google CSP Evaluator</a></li>
            <li><a href="https://report-uri.com/home/generate">CSP Policy Generator</a></li>
          </ul>
        `;
    }
  }

  private static mapSeverityToCaido(
    severity: CspVulnerability["severity"],
  ): string {
    // Map our severity levels to Caido's expected format
    const severityMap = {
      high: "high",
      medium: "medium",
      low: "low",
      info: "info",
    };

    return severityMap[severity] || "info";
  }

  static generateSummaryReport(vulnerabilities: CspVulnerability[]): string {
    if (vulnerabilities.length === 0) {
      return "No CSP vulnerabilities detected.";
    }

    const stats = this.getVulnerabilityStats(vulnerabilities);
    const groupedByType = this.groupByType(vulnerabilities);

    const sections = [
      `<h2>CSP Analysis Summary</h2>`,
      `<p><strong>Total Issues Found:</strong> ${stats.total}</p>`,
      `<ul>`,
      `  <li>High Severity: ${stats.high}</li>`,
      `  <li>Medium Severity: ${stats.medium}</li>`,
      `  <li>Low Severity: ${stats.low}</li>`,
      `  <li>Informational: ${stats.info}</li>`,
      `</ul>`,
      `<h3>Issues by Type</h3>`,
    ];

    for (const [type, vulns] of Object.entries(groupedByType)) {
      const rule =
        VULNERABILITY_RULES[type as keyof typeof VULNERABILITY_RULES];
      sections.push(
        `<p><strong>${rule.title}:</strong> ${vulns.length} instance(s)</p>`,
      );
    }

    return sections.join("\n");
  }

  private static getVulnerabilityStats(
    vulnerabilities: CspVulnerability[],
  ): Record<string, number> {
    const stats = { high: 0, medium: 0, low: 0, info: 0, total: 0 };

    for (const vuln of vulnerabilities) {
      stats[vuln.severity]++;
      stats.total++;
    }

    return stats;
  }

  private static groupByType(
    vulnerabilities: CspVulnerability[],
  ): Record<string, CspVulnerability[]> {
    const grouped: Record<string, CspVulnerability[]> = {};

    for (const vuln of vulnerabilities) {
      if (!grouped[vuln.type]) {
        grouped[vuln.type] = [];
      }
      grouped[vuln.type]?.push(vuln);
    }

    return grouped;
  }

  static async cleanupOldFindings(
    sdk: SDK,
    maxAge: number = 24 * 60 * 60 * 1000,
  ): Promise<void> {
    // This would need to be implemented based on Caido's findings API
    // For now, we'll just log the intent
    sdk.console.log(`Would cleanup CSP findings older than ${maxAge}ms`);
  }
}
