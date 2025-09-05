import type { CspAnalysisResult } from "./types";

/**
 * Next-Generation CSP Policy Generator
 * Advanced recommendations beyond legacy limitations
 */
export class EnhancedPolicyGenerator {
  /**
   * Generate modern, secure CSP policy recommendations
   */
  static generateSecurePolicy(
    options: {
      allowInlineStyles?: boolean;
      allowInlineScripts?: boolean;
      useStrictDynamic?: boolean;
      enableTrustedTypes?: boolean;
      allowDataUris?: boolean;
      includeCsp3Features?: boolean;
    } = {},
  ): string {
    const directives: string[] = [];

    // Modern default-src (strict by default)
    directives.push("default-src 'self'");

    // Enhanced script-src with modern security
    let scriptSrc = "script-src 'self'";

    if (options.useStrictDynamic) {
      // CSP Level 3 strict-dynamic for modern apps
      scriptSrc += " 'strict-dynamic'";
    }

    if (options.allowInlineScripts) {
      // Discouraged but provide guidance
      scriptSrc += " 'unsafe-inline'";
    } else {
      // Recommend nonce/hash approach
      scriptSrc += " 'nonce-{GENERATED_NONCE}'";
    }

    if (!options.allowDataUris) {
      // Block data: URIs by default
      scriptSrc += " 'unsafe-eval'"; // Remove this - typo, should not add unsafe-eval when blocking data
      scriptSrc = scriptSrc.replace(" 'unsafe-eval'", ""); // Fix the typo
    }

    directives.push(scriptSrc);

    // Modern style-src
    let styleSrc = "style-src 'self'";
    if (options.allowInlineStyles) {
      styleSrc += " 'unsafe-inline'";
    } else {
      styleSrc += " 'nonce-{GENERATED_NONCE}'";
    }
    directives.push(styleSrc);

    // Security-focused directives
    directives.push("object-src 'none'"); // Block plugins/objects entirely
    directives.push("base-uri 'self'"); // Prevent base tag injection
    directives.push("frame-ancestors 'self'"); // Clickjacking protection
    directives.push("form-action 'self'"); // Form submission protection
    directives.push("upgrade-insecure-requests"); // Force HTTPS

    // CSP Level 3 features
    if (options.enableTrustedTypes && options.includeCsp3Features) {
      directives.push("trusted-types default");
      directives.push("require-trusted-types-for 'script'");
    }

    // Modern media directives
    directives.push("media-src 'self' data:");
    directives.push("img-src 'self' data: https:");
    directives.push("font-src 'self' data:");

    // Worker and frame restrictions
    directives.push("worker-src 'self'");
    directives.push("child-src 'self'");
    directives.push("frame-src 'self'");

    // Manifest and prefetch
    directives.push("manifest-src 'self'");
    directives.push("prefetch-src 'self'");

    return directives.join("; ") + ";";
  }

  /**
   * Generate CSP based on analysis of existing policies
   */
  static generatePolicyFromAnalysis(analyses: CspAnalysisResult[]): {
    recommendedPolicy: string;
    reasoning: string[];
    securityImprovements: string[];
  } {
    const reasoning: string[] = [];
    const securityImprovements: string[] = [];

    // Analyze current vulnerabilities
    const allVulns = analyses.flatMap((a) => a.vulnerabilities);
    const vulnTypes = new Set(allVulns.map((v) => v.type));

    reasoning.push(
      `Analyzed ${analyses.length} CSP policies with ${allVulns.length} vulnerabilities`,
    );

    // Determine security level needed
    const hasHighSeverity = allVulns.some((v) => v.severity === "high");
    const hasScriptVulns =
      vulnTypes.has("script-wildcard") ||
      vulnTypes.has("script-unsafe-inline") ||
      vulnTypes.has("script-unsafe-eval");

    let securityLevel: "strict" | "balanced" | "permissive" = "balanced";

    if (hasHighSeverity || hasScriptVulns) {
      securityLevel = "strict";
      reasoning.push(
        "High-severity vulnerabilities detected - recommending strict policy",
      );
    }

    // Generate policy based on analysis
    const policyOptions = {
      allowInlineStyles: securityLevel !== "strict",
      allowInlineScripts: false, // Never recommend this
      useStrictDynamic: securityLevel === "strict",
      enableTrustedTypes: true,
      allowDataUris: false, // securityLevel === 'permissive' - removed invalid comparison
      includeCsp3Features: true,
    };

    const recommendedPolicy = this.generateSecurePolicy(policyOptions);

    // Generate security improvements
    if (vulnTypes.has("script-wildcard")) {
      securityImprovements.push(
        "Remove script-src wildcards and specify exact domains",
      );
    }

    if (vulnTypes.has("script-unsafe-inline")) {
      securityImprovements.push(
        "Replace 'unsafe-inline' with nonces or hashes",
      );
    }

    if (vulnTypes.has("deprecated-header")) {
      securityImprovements.push("Use modern Content-Security-Policy header");
    }

    if (vulnTypes.has("missing-trusted-types")) {
      securityImprovements.push("Enable Trusted Types for DOM XSS protection");
    }

    return {
      recommendedPolicy,
      reasoning,
      securityImprovements,
    };
  }

  /**
   * Generate CSP for specific application types
   */
  static generatePolicyForAppType(
    appType: "spa" | "static" | "ecommerce" | "media" | "enterprise",
  ): {
    policy: string;
    description: string;
    additionalRecommendations: string[];
  } {
    const recommendations: string[] = [];
    let policy: string;
    let description: string;

    switch (appType) {
      case "spa":
        policy = this.generateSecurePolicy({
          allowInlineStyles: false,
          allowInlineScripts: false,
          useStrictDynamic: true,
          enableTrustedTypes: true,
          includeCsp3Features: true,
        });
        description =
          "Strict CSP for Single Page Applications with modern security features";
        recommendations.push(
          "Implement nonce generation for dynamic script loading",
        );
        recommendations.push("Use Trusted Types to prevent DOM XSS");
        recommendations.push(
          "Consider using 'strict-dynamic' for third-party script dependencies",
        );
        break;

      case "static":
        policy =
          "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
          "img-src 'self' data: https:; font-src 'self'; base-uri 'self'; " +
          "frame-ancestors 'none'; upgrade-insecure-requests;";
        description =
          "Ultra-strict CSP for static websites with minimal attack surface";
        recommendations.push(
          "Remove 'unsafe-inline' from style-src when possible",
        );
        recommendations.push("Use frame-ancestors 'none' to prevent embedding");
        break;

      case "ecommerce":
        policy =
          this.generateSecurePolicy({
            allowInlineStyles: true, // Payment forms often need inline styles
            allowInlineScripts: false,
            useStrictDynamic: false,
            enableTrustedTypes: true,
          }) +
          " connect-src 'self' https://api.stripe.com https://api.paypal.com;";
        description =
          "Balanced CSP for e-commerce with payment processor integration";
        recommendations.push(
          "Whitelist only necessary payment processor domains",
        );
        recommendations.push(
          "Use subresource integrity (SRI) for payment scripts",
        );
        recommendations.push("Monitor for new payment integration domains");
        break;

      case "media":
        policy = this.generateSecurePolicy({
          allowInlineStyles: true,
          allowInlineScripts: false,
        }).replace(
          "media-src 'self' data:",
          "media-src 'self' data: https: blob:",
        );
        description = "Media-optimized CSP allowing various content sources";
        recommendations.push(
          "Be cautious with blob: URLs as they can be exploited",
        );
        recommendations.push(
          "Consider using specific CDN domains instead of https:",
        );
        break;

      case "enterprise":
        policy =
          this.generateSecurePolicy({
            allowInlineStyles: false,
            allowInlineScripts: false,
            useStrictDynamic: true,
            enableTrustedTypes: true,
            includeCsp3Features: true,
          }) + " report-uri /csp-report; report-to csp-endpoint;";
        description = "Enterprise-grade CSP with comprehensive monitoring";
        recommendations.push(
          "Implement CSP reporting endpoint for violation monitoring",
        );
        recommendations.push("Use CSP report-to directive for modern browsers");
        recommendations.push(
          "Regularly audit and update CSP based on violation reports",
        );
        recommendations.push(
          "Train development team on CSP-compliant coding practices",
        );
        break;

      default:
        policy = this.generateSecurePolicy();
        description = "General-purpose secure CSP";
    }

    return {
      policy,
      description,
      additionalRecommendations: recommendations,
    };
  }

  /**
   * Generate migration strategy from current to recommended policy
   */
  static generateMigrationStrategy(
    currentAnalysis: CspAnalysisResult,
    targetPolicy: string,
  ): {
    steps: Array<{
      step: number;
      description: string;
      policy: string;
      risk: "low" | "medium" | "high";
    }>;
    timeline: string;
    riskAssessment: string;
  } {
    const steps: Array<{
      step: number;
      description: string;
      policy: string;
      risk: "low" | "medium" | "high";
    }> = [];

    // Phase 1: Deploy in report-only mode
    steps.push({
      step: 1,
      description:
        "Deploy recommended policy in Content-Security-Policy-Report-Only mode",
      policy: targetPolicy.replace(/;$/, "; report-uri /csp-report;"),
      risk: "low",
    });

    // Phase 2: Fix critical violations
    steps.push({
      step: 2,
      description:
        "Fix critical violations reported in phase 1 (typically 1-2 weeks)",
      policy: "Continue monitoring report-only mode",
      risk: "low",
    });

    // Phase 3: Gradual enforcement
    steps.push({
      step: 3,
      description: "Deploy enforcing policy with relaxed settings",
      policy: targetPolicy
        .replace("'strict-dynamic'", "'unsafe-inline'")
        .replace("'none'", "'self'"),
      risk: "medium",
    });

    // Phase 4: Full enforcement
    steps.push({
      step: 4,
      description: "Deploy final strict policy after validation",
      policy: targetPolicy,
      risk: "high",
    });

    const timeline =
      "Recommended timeline: 4-8 weeks depending on application complexity";
    const riskAssessment =
      "Progressive deployment minimizes risk of breaking application functionality";

    return {
      steps,
      timeline,
      riskAssessment,
    };
  }

  /**
   * Validate and score CSP policy strength
   */
  static scorePolicyStrength(policy: string): {
    score: number; // 0-100
    grade: "A+" | "A" | "B" | "C" | "D" | "F";
    strengths: string[];
    weaknesses: string[];
    recommendations: string[];
  } {
    let score = 0;
    const strengths: string[] = [];
    const weaknesses: string[] = [];
    const recommendations: string[] = [];

    // Parse policy directives
    const directives = policy
      .split(";")
      .map((d) => d.trim())
      .filter((d) => d);
    const directiveMap = new Map<string, string[]>();

    for (const directive of directives) {
      const parts = directive.split(/\s+/);
      const name = parts[0];
      const values = parts.slice(1);
      if (name) {
        directiveMap.set(name, values);
      }
    }

    // Scoring criteria

    // Essential directives (40 points total)
    const essential = ["default-src", "script-src", "object-src", "base-uri"];
    let essentialCount = 0;
    for (const dir of essential) {
      if (directiveMap.has(dir)) {
        essentialCount++;
        score += 10;
      } else {
        weaknesses.push(`Missing essential directive: ${dir}`);
      }
    }

    // Security features (30 points total)
    if (directiveMap.get("object-src")?.includes("'none'")) {
      score += 10;
      strengths.push("Objects/plugins completely blocked");
    }

    if (directiveMap.has("upgrade-insecure-requests")) {
      score += 10;
      strengths.push("Enforces HTTPS");
    }

    if (directiveMap.has("frame-ancestors")) {
      score += 10;
      strengths.push("Clickjacking protection enabled");
    }

    // Modern features (20 points total)
    if (directiveMap.has("trusted-types")) {
      score += 10;
      strengths.push("Trusted Types enabled");
    }

    if (directiveMap.has("require-trusted-types-for")) {
      score += 10;
      strengths.push("Trusted Types required for scripts");
    }

    // Penalize unsafe practices (-30 points possible)
    const scriptSrc = directiveMap.get("script-src") || [];
    if (scriptSrc.includes("*")) {
      score -= 15;
      weaknesses.push("Script wildcards allow any domain");
    }
    if (scriptSrc.includes("'unsafe-inline'")) {
      score -= 10;
      weaknesses.push("Unsafe inline scripts allowed");
    }
    if (scriptSrc.includes("'unsafe-eval'")) {
      score -= 5;
      weaknesses.push("Dynamic code execution allowed");
    }

    // Bonus for reporting (10 points)
    if (directiveMap.has("report-uri") || directiveMap.has("report-to")) {
      score += 10;
      strengths.push("CSP violation reporting configured");
    }

    // Determine grade
    let grade: "A+" | "A" | "B" | "C" | "D" | "F";
    if (score >= 95) grade = "A+";
    else if (score >= 85) grade = "A";
    else if (score >= 75) grade = "B";
    else if (score >= 65) grade = "C";
    else if (score >= 55) grade = "D";
    else grade = "F";

    // Generate recommendations
    if (score < 80) {
      recommendations.push("Consider implementing a stricter CSP policy");
    }
    if (!directiveMap.has("trusted-types")) {
      recommendations.push(
        "Enable Trusted Types for enhanced DOM XSS protection",
      );
    }
    if (!directiveMap.has("report-uri")) {
      recommendations.push("Add CSP reporting to monitor violations");
    }

    return {
      score: Math.max(0, Math.min(100, score)),
      grade,
      strengths,
      weaknesses,
      recommendations,
    };
  }
}
