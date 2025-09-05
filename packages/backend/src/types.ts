export interface CspSource {
  value: string;
  type: "keyword" | "scheme" | "host" | "nonce" | "hash" | "unsafe";
  isWildcard: boolean;
  isUnsafe: boolean;
}

export interface CspDirective {
  name: string;
  values: string[];
  implicit: boolean;
  sources: CspSource[];
}

export interface CspPolicy {
  id: string;
  requestId: string;
  headerName: string;
  headerValue: string;
  directives: Map<string, CspDirective>;
  isReportOnly: boolean;
  isDeprecated: boolean;
  parsedAt: Date;
  url?: string;
}

export type VulnerabilityType =
  // Legacy vulnerabilities
  | "script-wildcard"
  | "script-unsafe-inline"
  | "script-unsafe-eval"
  | "style-wildcard"
  | "style-unsafe-inline"
  | "user-content-host"
  | "vulnerable-js-host"
  | "deprecated-header"
  | "wildcard-limited"

  // Enhanced modern vulnerabilities
  | "script-data-uri"
  | "object-wildcard"
  | "jsonp-bypass-risk"
  | "angularjs-bypass"
  | "missing-trusted-types"
  | "missing-require-trusted-types"
  | "missing-essential-directive"
  | "permissive-base-uri"
  | "nonce-unsafe-inline-conflict"

  // Modern threat categories
  | "ai-ml-host"
  | "web3-host"
  | "cdn-supply-chain"
  | "supply-chain-risk"
  | "privacy-tracking-risk"
  | "gaming-metaverse-risk";

export type Severity = "high" | "medium" | "low" | "info";

export interface CspVulnerability {
  id: string;
  type: VulnerabilityType;
  severity: Severity;
  directive: string;
  value: string;
  description: string;
  remediation: string;
  cweId?: number;
  requestId: string;
}

export interface CspAnalysisResult {
  requestId: string;
  policies: CspPolicy[];
  vulnerabilities: CspVulnerability[];
  analyzedAt: Date;
}

export interface CspCheckSettings {
  [key: string]: {
    enabled: boolean;
    name: string;
    category: string;
    severity: Severity;
    description: string;
  };
}
