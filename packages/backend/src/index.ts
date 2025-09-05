import type { DefineAPI, SDK } from "caido:plugin";

import { CspParser } from './csp-parser';
import { EnhancedCspAnalyzer } from './enhanced-analyzer';
import type { CspAnalysisResult, CspPolicy, CspVulnerability } from "./types";

const analysisCache = new Map<string, CspAnalysisResult>();
let respectScope = true;
let createFindings = false;

// Default CSP check settings - all enabled by default
let cspCheckSettings: Record<string, boolean> = {
  'script-wildcard': true,
  'script-unsafe-inline': true,
  'script-unsafe-eval': true,
  'script-data-uri': true,
  'object-wildcard': true,
  'jsonp-bypass-risk': true,
  'angularjs-bypass': true,
  'ai-ml-host': true,
  'web3-host': true,
  'cdn-supply-chain': true,
  'missing-trusted-types': true,
  'missing-require-trusted-types': true,
  'missing-essential-directive': true,
  'permissive-base-uri': true,
  'style-wildcard': true,
  'style-unsafe-inline': true,
  'deprecated-header': true,
  'user-content-host': true,
  'vulnerable-js-host': true,
  'nonce-unsafe-inline-conflict': true,
};

const analyzeCspHeaders = async (
  sdk: SDK,
  requestId: string,
): Promise<CspAnalysisResult | null> => {
  try {
    if (analysisCache.has(requestId)) {
      return analysisCache.get(requestId)!;
    }

    return {
      requestId,
      policies: [],
      vulnerabilities: [],
      analyzedAt: new Date()
    };
  } catch (error) {
    sdk.console.error(
      `CSP analysis failed for ${requestId}: ${error instanceof Error ? error.message : String(error)}`,
    );
    return null;
  }
};

const getCspAnalysis = async (
  sdk: SDK,
  requestId: string,
): Promise<CspAnalysisResult | null> => {
  return analysisCache.get(requestId) || null;
};

const getAllCspAnalyses = async (sdk: SDK): Promise<CspAnalysisResult[]> => {
  return Array.from(analysisCache.values()).sort(
    (a, b) => b.analyzedAt.getTime() - a.analyzedAt.getTime(),
  );
};

const getCspStats = async (sdk: SDK): Promise<Record<string, any>> => {
  try {
    const analyses = Array.from(analysisCache.values());

    const stats = {
      totalAnalyses: analyses.length,
      totalVulnerabilities: analyses.reduce((sum, analysis) => sum + analysis.vulnerabilities.length, 0),
      severityStats: {
        high: analyses.reduce((sum, a) => sum + a.vulnerabilities.filter(v => v.severity === 'high').length, 0),
        medium: analyses.reduce((sum, a) => sum + a.vulnerabilities.filter(v => v.severity === 'medium').length, 0),
        low: analyses.reduce((sum, a) => sum + a.vulnerabilities.filter(v => v.severity === 'low').length, 0),
        info: analyses.reduce((sum, a) => sum + a.vulnerabilities.filter(v => v.severity === 'info').length, 0)
      },
      typeStats: {},
      lastAnalyzed: analyses.length > 0 ? new Date() : null,
    };

    for (const analysis of analyses) {
      for (const vuln of analysis.vulnerabilities) {
        (stats.typeStats as any)[vuln.type] = ((stats.typeStats as any)[vuln.type] || 0) + 1;
      }
    }

    return stats;
  } catch (error) {
    return {
      totalAnalyses: 0,
      totalVulnerabilities: 0,
      severityStats: { high: 0, medium: 0, low: 0, info: 0 },
      typeStats: {},
      lastAnalyzed: null,
    };
  }
};

const exportCspFindings = async (
  sdk: SDK,
  format: "json" | "csv" = "json",
): Promise<string> => {
  const analyses = await getAllCspAnalyses(sdk);
  const allVulnerabilities = analyses.flatMap((a) => a.vulnerabilities);

  if (format === "json") {
    return JSON.stringify(
      {
        exportedAt: new Date().toISOString(),
        totalFindings: allVulnerabilities.length,
        findings: allVulnerabilities,
      },
      null,
      2,
    );
  } else {
    const headers = [
      "ID",
      "Type",
      "Severity",
      "Directive",
      "Value",
      "Description",
      "Request ID",
    ];
    const rows = allVulnerabilities.map((vuln) => [
      vuln.id,
      vuln.type,
      vuln.severity,
      vuln.directive,
      vuln.value,
      vuln.description.replace(/[",]/g, ""),
      vuln.requestId,
    ]);

    return [headers, ...rows].map((row) => row.join(",")).join("\n");
  }
};

const clearCspCache = async (sdk: SDK): Promise<void> => {
  const count = analysisCache.size;
  analysisCache.clear();
  sdk.console.log(`Cleared CSP analysis cache (${count} entries)`);
};

const processWorkflowCspAnalysis = async (
  sdk: SDK,
  requestData: { id: string; host: string; path: string },
  responseData: { headers: Record<string, string[]> },
  request?: any
): Promise<CspAnalysisResult | null> => {
  try {
    const requestId = requestData.id;
    const url = `${requestData.host}${requestData.path}`;

    const cspHeadersData = CspParser.extractCspHeaders(responseData.headers);

    if (cspHeadersData.length === 0) {
      return null;
    }

    const policies: CspPolicy[] = [];
    const allVulnerabilities: CspVulnerability[] = [];

    for (const headerData of cspHeadersData) {
      const policy = CspParser.parsePolicy(
        headerData.name,
        headerData.value,
        requestId,
        url
      );
      policies.push(policy);

      const vulnerabilities = EnhancedCspAnalyzer.analyzePolicy(policy, cspCheckSettings);
      allVulnerabilities.push(...vulnerabilities);
    }

    const analysisResult: CspAnalysisResult = {
      requestId,
      policies,
      vulnerabilities: allVulnerabilities,
      analyzedAt: new Date()
    };

    analysisCache.set(requestId, analysisResult);

    sdk.console.log(`CSP Analysis complete: ${allVulnerabilities.length} vulnerabilities found, createFindings: ${createFindings}`);

    if (createFindings && allVulnerabilities.length > 0 && request) {
      try {
        const title = `CSP Vulnerabilities - ${policies.length} polic${policies.length === 1 ? 'y' : 'ies'} found`;
        const description = `Found ${allVulnerabilities.length} CSP vulnerability/vulnerabilities across ${policies.length} polic${policies.length === 1 ? 'y' : 'ies'}:\n\n` +
          allVulnerabilities.map(vuln => 
            `• ${vuln.type} (${vuln.severity}): ${vuln.directive} - ${vuln.description}`
          ).join('\n');

        await sdk.findings.create({
          title,
          description,
          reporter: "CSP Auditor",
          request,
          dedupeKey: `csp-${requestData.host}-${requestData.path}`
        });

        sdk.console.log(`Created finding for CSP vulnerabilities in ${requestId}`);
      } catch (error) {
        sdk.console.error(`Failed to create finding: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    return analysisResult;
  } catch (error) {
    sdk.console.error(`CSP analysis failed: ${error instanceof Error ? error.message : String(error)}`);
    return null;
  }
};


const setScopeRespecting = async (sdk: SDK, respectScopeEnabled: boolean): Promise<void> => {
  respectScope = respectScopeEnabled;
  sdk.console.log(`CSP Auditor scope setting updated: ${respectScope ? 'respecting scope' : 'ignoring scope'}`);
};

const getScopeRespecting = async (sdk: SDK): Promise<boolean> => {
  return respectScope;
};

const setCreateFindings = async (sdk: SDK, createFindingsEnabled: boolean): Promise<void> => {
  createFindings = createFindingsEnabled;
  sdk.console.log(`CSP Auditor findings creation updated: ${createFindings ? 'enabled' : 'disabled'} (value: ${createFindings})`);
};

const getCreateFindings = async (sdk: SDK): Promise<boolean> => {
  return createFindings;
};

const getCspCheckSettings = async (sdk: SDK): Promise<Record<string, boolean>> => {
  return cspCheckSettings;
};

const setCspCheckSettings = async (sdk: SDK, settings: Record<string, boolean>): Promise<void> => {
  cspCheckSettings = { ...settings };
  sdk.console.log(`CSP check settings updated: ${Object.keys(settings).length} checks configured`);
};

const updateCspCheckSetting = async (sdk: SDK, checkId: string, enabled: boolean): Promise<void> => {
  cspCheckSettings[checkId] = enabled;
  sdk.console.log(`CSP check setting updated: ${checkId} = ${enabled}`);
};

export type API = DefineAPI<{
  analyzeCspHeaders: typeof analyzeCspHeaders;
  getCspAnalysis: typeof getCspAnalysis;
  getAllCspAnalyses: typeof getAllCspAnalyses;
  getCspStats: typeof getCspStats;
  exportCspFindings: typeof exportCspFindings;
  clearCspCache: typeof clearCspCache;
  processWorkflowCspAnalysis: typeof processWorkflowCspAnalysis;
  setScopeRespecting: typeof setScopeRespecting;
  getScopeRespecting: typeof getScopeRespecting;
  setCreateFindings: typeof setCreateFindings;
  getCreateFindings: typeof getCreateFindings;
  getCspCheckSettings: typeof getCspCheckSettings;
  setCspCheckSettings: typeof setCspCheckSettings;
  updateCspCheckSetting: typeof updateCspCheckSetting;
}>;

export function init(sdk: SDK<API>) {
  sdk.api.register("analyzeCspHeaders", analyzeCspHeaders);
  sdk.api.register("getCspAnalysis", getCspAnalysis);
  sdk.api.register("getAllCspAnalyses", getAllCspAnalyses);
  sdk.api.register("getCspStats", getCspStats);
  sdk.api.register("exportCspFindings", exportCspFindings);
  sdk.api.register("clearCspCache", clearCspCache);
  sdk.api.register("processWorkflowCspAnalysis", processWorkflowCspAnalysis);
  sdk.api.register("setScopeRespecting", setScopeRespecting);
  sdk.api.register("getScopeRespecting", getScopeRespecting);
  sdk.api.register("setCreateFindings", setCreateFindings);
  sdk.api.register("getCreateFindings", getCreateFindings);
  sdk.api.register("getCspCheckSettings", getCspCheckSettings);
  sdk.api.register("setCspCheckSettings", setCspCheckSettings);
  sdk.api.register("updateCspCheckSetting", updateCspCheckSetting);

  try {
    sdk.events.onInterceptResponse(async (sdk, request, response) => {
      try {
        const responseHeaders = response.getHeaders();
        const headerNames = Object.keys(responseHeaders).map(h => h.toLowerCase());
        const cspHeaderNames = headerNames.filter(h =>
          h.includes('content-security-policy') ||
          h.includes('x-content-security-policy') ||
          h.includes('x-webkit-csp')
        );

        if (cspHeaderNames.length > 0) {
          if (respectScope) {
            const inScope = sdk.requests.inScope(request);
            if (!inScope) {
              return;
            }
          }

          const requestData = {
            id: request.getId(),
            host: request.getHost(),
            path: request.getPath()
          };

          const responseData = {
            headers: responseHeaders
          };

          await processWorkflowCspAnalysis(sdk, requestData, responseData, request);
        }
      } catch (error) {
        sdk.console.error(`Error processing response: ${error}`);
      }
    });
  } catch (error) {
    sdk.console.warn(`Could not enable real-time monitoring: ${error}`);
  }
}
