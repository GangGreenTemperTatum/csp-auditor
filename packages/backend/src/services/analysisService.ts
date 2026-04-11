import type { Request } from "caido:utils";
import type {
  AnalysisResult,
  AnalysisSummary,
  ParsedPolicy,
  PolicyFinding,
  SeverityLevel,
} from "shared";

import { buildDefaultCheckState } from "../data";
import { analyzePolicy, extractCspHeaders, parsePolicyHeader } from "../engine";
import { requireSDK } from "../sdk";

const analysisCache = new Map<string, AnalysisResult>();
let scopeEnabled = true;
let findingsEnabled = false;
let checkSettings: Record<string, boolean> = buildDefaultCheckState();

type RequestData = {
  id: string;
  host: string;
  path: string;
};

type ResponseData = {
  headers: Record<string, string[]>;
};

export async function processResponse(
  requestData: RequestData,
  responseData: ResponseData,
  request?: Request,
): Promise<AnalysisResult | undefined> {
  const sdk = requireSDK();
  const url = `${requestData.host}${requestData.path}`;
  const cspHeaders = extractCspHeaders(responseData.headers);

  if (cspHeaders.length === 0) return undefined;

  const policies: ParsedPolicy[] = [];
  const allFindings: PolicyFinding[] = [];

  for (const header of cspHeaders) {
    const policy = parsePolicyHeader(
      header.name,
      header.value,
      requestData.id,
      url,
    );
    policies.push(policy);
    allFindings.push(...analyzePolicy(policy, checkSettings));
  }

  const result: AnalysisResult = {
    requestId: requestData.id,
    policies,
    findings: allFindings,
    analyzedAt: new Date(),
  };

  analysisCache.set(requestData.id, result);
  sdk.api.send("analysisUpdated");

  if (findingsEnabled && allFindings.length > 0 && request !== undefined) {
    const highCount = allFindings.filter((f) => f.severity === "high").length;
    const medCount = allFindings.filter((f) => f.severity === "medium").length;
    const title = `CSP: ${allFindings.length} issues found (${highCount} high, ${medCount} medium)`;
    const lines = allFindings.map(
      (f) =>
        `**${f.checkId}** (${f.severity.toUpperCase()}) - ${f.directive}\n` +
        `${f.description}\n` +
        `**Remediation:** ${f.remediation}`,
    );
    const description = lines.join("\n\n");

    await sdk.findings.create({
      title,
      description,
      reporter: "CSP Auditor",
      request,
      dedupeKey: `csp-${requestData.host}-${requestData.path}`,
    });
  }

  return result;
}

export function getAnalysis(requestId: string): AnalysisResult | undefined {
  return analysisCache.get(requestId);
}

export function getAllAnalyses(): AnalysisResult[] {
  return Array.from(analysisCache.values()).sort(
    (a, b) => b.analyzedAt.getTime() - a.analyzedAt.getTime(),
  );
}

export function computeSummary(): AnalysisSummary {
  const analyses = Array.from(analysisCache.values());
  const allFindings = analyses.flatMap((a) => a.findings);

  const severityCounts: Record<SeverityLevel, number> = {
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  const checkIdCounts: Record<string, number> = {};

  for (const finding of allFindings) {
    severityCounts[finding.severity]++;
    checkIdCounts[finding.checkId] = (checkIdCounts[finding.checkId] ?? 0) + 1;
  }

  return {
    totalAnalyses: analyses.length,
    totalFindings: allFindings.length,
    severityCounts,
    checkIdCounts,
    lastAnalyzedAt: analyses.length > 0 ? analyses[0]?.analyzedAt : undefined,
  };
}

export function clearCache(): void {
  analysisCache.clear();
  requireSDK().api.send("analysisUpdated");
}

export function getScopeEnabled(): boolean {
  return scopeEnabled;
}

export function setScopeEnabled(enabled: boolean): void {
  scopeEnabled = enabled;
}

export function getFindingsEnabled(): boolean {
  return findingsEnabled;
}

export function setFindingsEnabled(enabled: boolean): void {
  findingsEnabled = enabled;
}

export function getCheckSettings(): Record<string, boolean> {
  return { ...checkSettings };
}

export function setCheckSettings(settings: Record<string, boolean>): void {
  checkSettings = { ...settings };
}

export function updateSingleCheck(checkId: string, enabled: boolean): void {
  checkSettings[checkId] = enabled;
}
