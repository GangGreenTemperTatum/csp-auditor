import type { ParsedPolicy } from "./csp";
import type { PolicyFinding, SeverityLevel } from "./vulnerability";

export type AnalysisResult = {
  requestId: string;
  policies: ParsedPolicy[];
  findings: PolicyFinding[];
  analyzedAt: Date;
};

export type AnalysisSummary = {
  totalAnalyses: number;
  totalFindings: number;
  severityCounts: Record<SeverityLevel, number>;
  checkIdCounts: Record<string, number>;
  lastAnalyzedAt: Date | undefined;
};
