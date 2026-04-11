import type { SDK } from "caido:plugin";
import type { AnalysisResult, AnalysisSummary, Result } from "shared";
import { ok } from "shared";

import {
  clearCache,
  computeSummary,
  getAllAnalyses,
  getAnalysis,
} from "../services";

export function apiGetAllAnalyses(_sdk: SDK): Result<AnalysisResult[]> {
  return ok(getAllAnalyses());
}

export function apiGetAnalysis(
  _sdk: SDK,
  requestId: string,
): Result<AnalysisResult | undefined> {
  return ok(getAnalysis(requestId));
}

export function apiGetSummary(_sdk: SDK): Result<AnalysisSummary> {
  return ok(computeSummary());
}

export function apiClearCache(_sdk: SDK): Result<void> {
  clearCache();
  return ok(undefined);
}
