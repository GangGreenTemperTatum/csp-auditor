export interface FrontendSDK {
  navigation: {
    addPage: (path: string, options: { body: HTMLElement }) => void;
  };
  sidebar: {
    registerItem: (title: string, path: string) => void;
  };
  backend: {
    getCspStats: () => Promise<CspStats>;
    getAllCspAnalyses: () => Promise<CspAnalysisResult[]>;
    getScopeRespecting: () => Promise<boolean>;
    getCreateFindings: () => Promise<boolean>;
    setScopeRespecting: (value: boolean) => Promise<void>;
    setCreateFindings: (value: boolean) => Promise<void>;
    clearCspCache: () => Promise<void>;
    exportCspFindings: (format: "json" | "csv") => Promise<string>;
    getCspCheckSettings: () => Promise<Record<string, boolean>>;
    setCspCheckSettings: (settings: Record<string, boolean>) => Promise<void>;
    updateCspCheckSetting: (checkId: string, enabled: boolean) => Promise<void>;
    getBypassDatabase: () => Promise<BypassEntry[]>;
    onEvent: (
      event: "analysisUpdated",
      callback: () => void,
    ) => { stop: () => void };
  };
}

export interface BypassEntry {
  domain: string;
  code: string;
  technique: string;
  id: string;
}

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
  lastAnalyzed: Date | undefined;
}

export interface FindingFilter {
  severity?: Severity[];
  types?: VulnerabilityType[];
  search?: string;
}
