import type { CheckId, SeverityLevel } from "./vulnerability";

export type ConfigurableCheckId =
  | "script-wildcard"
  | "script-unsafe-inline"
  | "script-unsafe-eval"
  | "script-data-uri"
  | "object-wildcard"
  | "jsonp-bypass-risk"
  | "angularjs-bypass"
  | "ai-ml-host"
  | "web3-host"
  | "cdn-supply-chain"
  | "missing-trusted-types"
  | "missing-require-trusted-types"
  | "missing-essential-directive"
  | "permissive-base-uri"
  | "style-wildcard"
  | "style-unsafe-inline"
  | "deprecated-header"
  | "user-content-host"
  | "vulnerable-js-host"
  | "nonce-unsafe-inline-conflict";

export type CheckCategory =
  | "Critical"
  | "Modern Threats"
  | "Missing Features"
  | "Policy Weaknesses"
  | "Style Issues"
  | "Legacy Issues"
  | "Advanced";

export type CheckDefinition = {
  name: string;
  category: CheckCategory;
  severity: SeverityLevel;
  description: string;
  remediation: string;
  cweId?: number;
};

export const CHECK_REGISTRY: Record<CheckId, CheckDefinition> = {
  "script-wildcard": {
    name: "Script Wildcard Sources",
    category: "Critical",
    severity: "high",
    description:
      "Allows script execution from any domain, completely bypassing CSP protection",
    remediation:
      "Remove '*' and specify exact trusted domains. Use nonces or hashes for inline scripts.",
    cweId: 79,
  },
  "script-unsafe-inline": {
    name: "Unsafe Inline Scripts",
    category: "Critical",
    severity: "high",
    description:
      "Permits inline JavaScript execution, enabling XSS attacks through script tags and event handlers",
    remediation:
      "Remove 'unsafe-inline'. Use nonces ('nonce-xyz123') or hashes ('sha256-...') for legitimate inline scripts.",
    cweId: 79,
  },
  "script-unsafe-eval": {
    name: "Unsafe Eval Execution",
    category: "Critical",
    severity: "high",
    description:
      "Enables eval(), Function() constructor, and setTimeout/setInterval with strings",
    remediation:
      "Remove 'unsafe-eval'. Refactor code to avoid dynamic code execution.",
    cweId: 94,
  },
  "script-data-uri": {
    name: "Data URI Script Execution",
    category: "Critical",
    severity: "high",
    description: "Allows base64-encoded JavaScript execution via data: URIs",
    remediation:
      "Remove 'data:' from script-src. Use proper script files or nonces/hashes.",
    cweId: 79,
  },
  "object-wildcard": {
    name: "Object Wildcard Sources",
    category: "Critical",
    severity: "high",
    description:
      "Allows loading objects/plugins from any source, potential for code execution",
    remediation: "Set object-src to 'none' or specify trusted sources only.",
    cweId: 79,
  },
  "jsonp-bypass-risk": {
    name: "JSONP Bypass Risk",
    category: "Modern Threats",
    severity: "high",
    description: "Host supports JSONP callbacks that can bypass CSP",
    remediation: "Remove JSONP-enabled hosts or use fetch() with proper CORS.",
    cweId: 79,
  },
  "angularjs-bypass": {
    name: "AngularJS Template Injection",
    category: "Modern Threats",
    severity: "high",
    description: "AngularJS versions allow template injection bypasses of CSP",
    remediation: "Upgrade to Angular 2+ or remove AngularJS entirely.",
    cweId: 79,
  },
  "ai-ml-host": {
    name: "AI/ML Service Endpoint Risk",
    category: "Modern Threats",
    severity: "medium",
    description:
      "AI/ML service endpoint detected - potential data exfiltration vector",
    remediation:
      "Review necessity of AI/ML service integration and implement additional security controls.",
  },
  "web3-host": {
    name: "Web3/Crypto Endpoint Risk",
    category: "Modern Threats",
    severity: "medium",
    description:
      "Web3/cryptocurrency endpoint detected - financial transaction risk",
    remediation:
      "Review necessity of Web3 integration and implement additional security controls.",
  },
  "cdn-supply-chain": {
    name: "CDN Supply Chain Risk",
    category: "Modern Threats",
    severity: "medium",
    description: "CDN endpoint with known supply chain attack history detected",
    remediation:
      "Use Subresource Integrity (SRI) or self-host critical assets.",
  },
  "missing-trusted-types": {
    name: "Trusted Types Not Configured",
    category: "Missing Features",
    severity: "medium",
    description:
      "Trusted Types policy not configured - DOM XSS protection unavailable",
    remediation: "Add 'trusted-types' directive to enable DOM XSS protection.",
  },
  "missing-require-trusted-types": {
    name: "Trusted Types Not Enforced",
    category: "Missing Features",
    severity: "medium",
    description: "DOM manipulation not restricted to Trusted Types",
    remediation: "Add 'require-trusted-types-for \"script\"' directive.",
  },
  "missing-essential-directive": {
    name: "Missing Essential Directives",
    category: "Missing Features",
    severity: "medium",
    description: "Critical security directive not defined",
    remediation: "Add the missing directive with appropriate values.",
  },
  "permissive-base-uri": {
    name: "Permissive Base URI",
    category: "Policy Weaknesses",
    severity: "medium",
    description: "Unrestricted base URI can enable injection attacks",
    remediation: "Set base-uri to 'self' or specific trusted origins.",
  },
  "style-wildcard": {
    name: "Style Wildcard Sources",
    category: "Style Issues",
    severity: "low",
    description: "Allows stylesheets from any domain",
    remediation: "Restrict style-src to specific trusted domains.",
    cweId: 79,
  },
  "style-unsafe-inline": {
    name: "Unsafe Inline Styles",
    category: "Style Issues",
    severity: "medium",
    description: "Permits inline CSS which can be used for data exfiltration",
    remediation:
      "Remove 'unsafe-inline' from style-src. Use nonces or hashes for inline styles.",
    cweId: 79,
  },
  "deprecated-header": {
    name: "Deprecated CSP Headers",
    category: "Legacy Issues",
    severity: "medium",
    description:
      "Using deprecated CSP header that may not be supported by modern browsers",
    remediation: "Use 'Content-Security-Policy' header instead.",
  },
  "user-content-host": {
    name: "User-Uploaded Content Hosts",
    category: "Legacy Issues",
    severity: "high",
    description:
      "Domain allows user-uploaded content that could contain malicious scripts",
    remediation:
      "Use Subresource Integrity (SRI), restrict to specific paths, or self-host assets.",
    cweId: 79,
  },
  "vulnerable-js-host": {
    name: "Vulnerable JS Library Hosts",
    category: "Legacy Issues",
    severity: "high",
    description: "Domain hosts known vulnerable JavaScript libraries",
    remediation:
      "Update to latest library versions, self-host, or use Subresource Integrity (SRI).",
    cweId: 79,
  },
  "nonce-unsafe-inline-conflict": {
    name: "Nonce/Unsafe-Inline Conflict",
    category: "Advanced",
    severity: "medium",
    description:
      "Nonce protection is bypassed when 'unsafe-inline' is also present",
    remediation:
      "Remove 'unsafe-inline' when using nonces for better security.",
  },
  "wildcard-limited": {
    name: "Limited Wildcard Usage",
    category: "Policy Weaknesses",
    severity: "low",
    description:
      "Wildcard source in non-script directive reduces policy effectiveness",
    remediation: "Replace wildcard with specific trusted domains.",
  },
  "supply-chain-risk": {
    name: "Supply Chain Risk",
    category: "Modern Threats",
    severity: "medium",
    description: "Third-party supply chain risk detected",
    remediation: "Review third-party dependencies and use SRI.",
  },
  "privacy-tracking-risk": {
    name: "Privacy Tracking Risk",
    category: "Modern Threats",
    severity: "low",
    description: "Privacy and tracking service endpoint detected",
    remediation: "Review tracking integrations for privacy compliance.",
  },
  "gaming-metaverse-risk": {
    name: "Gaming/Metaverse Risk",
    category: "Modern Threats",
    severity: "low",
    description: "Gaming/metaverse service endpoint detected",
    remediation: "Review gaming platform integrations for content security.",
  },
};

const NON_CONFIGURABLE_IDS = new Set([
  "wildcard-limited",
  "supply-chain-risk",
  "privacy-tracking-risk",
  "gaming-metaverse-risk",
]);

export const DEFAULT_CHECK_DEFINITIONS = Object.fromEntries(
  Object.entries(CHECK_REGISTRY).filter(
    ([id]) => !NON_CONFIGURABLE_IDS.has(id),
  ),
) as Record<ConfigurableCheckId, CheckDefinition>;
