import type { API } from '@caido/sdk-frontend';

// Define the backend endpoints that our plugin provides
// Note: These match the actual backend function signatures (without SDK parameter)
export type BackendEndpoints = {
  analyzeCspHeaders: (requestId: string) => Promise<CspAnalysisResult | null>;
  getCspAnalysis: (requestId: string) => Promise<CspAnalysisResult | null>;
  getAllCspAnalyses: () => Promise<CspAnalysisResult[]>;
  getCspStats: () => Promise<CspStats>;
  exportCspFindings: (format?: "json" | "csv") => Promise<string>;
  clearCspCache: () => Promise<void>;
  processWorkflowCspAnalysis: (
    requestData: { id: string; host: string; path: string },
    responseData: { headers: Record<string, string[]> }
  ) => Promise<CspAnalysisResult | null>;
};

// Use proper Caido SDK type
export type FrontendSDK = API<BackendEndpoints, {}>;

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
  | "script-wildcard"
  | "script-unsafe-inline"
  | "script-unsafe-eval"
  | "style-wildcard"
  | "style-unsafe-inline"
  | "user-content-host"
  | "vulnerable-js-host"
  | "deprecated-header"
  | "wildcard-limited";

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

export interface CspStats {
  totalAnalyses: number;
  totalVulnerabilities: number;
  severityStats: {
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  typeStats: Record<string, number>;
  lastAnalyzed: Date | null;
}

export interface FindingFilter {
  severity?: Severity[];
  types?: VulnerabilityType[];
  search?: string;
}
