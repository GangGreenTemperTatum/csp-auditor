import { defineStore, storeToRefs } from "pinia";
import type { AnalysisResult, AnalysisSummary, SeverityLevel } from "shared";
import { computed } from "vue";

import { useSDK } from "@/plugins/sdk";
import { useAnalysesStore } from "@/stores/analyses";

export const useAnalysesService = defineStore("services.analyses", () => {
  const sdk = useSDK();
  const store = useAnalysesStore();
  const { state } = storeToRefs(store);
  let eventRegistered = false;

  const summary = computed((): AnalysisSummary => {
    const current = state.value;
    if (current.type !== "Success") {
      return {
        totalAnalyses: 0,
        totalFindings: 0,
        severityCounts: { high: 0, medium: 0, low: 0, info: 0 },
        checkIdCounts: {},
        lastAnalyzedAt: undefined,
      };
    }

    const analyses = current.analyses;
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
      checkIdCounts[finding.checkId] =
        (checkIdCounts[finding.checkId] ?? 0) + 1;
    }

    let lastAnalyzedAt: Date | undefined;
    for (const a of analyses) {
      if (
        lastAnalyzedAt === undefined ||
        a.analyzedAt.getTime() > lastAnalyzedAt.getTime()
      ) {
        lastAnalyzedAt = a.analyzedAt;
      }
    }

    return {
      totalAnalyses: analyses.length,
      totalFindings: allFindings.length,
      severityCounts,
      checkIdCounts,
      lastAnalyzedAt,
    };
  });

  const initialize = async () => {
    store.send({ type: "Start" });
    await loadAnalyses();

    if (!eventRegistered) {
      eventRegistered = true;
      sdk.backend.onEvent("analysisUpdated", async () => {
        await loadAnalyses();
      });
    }
  };

  const loadAnalyses = async () => {
    const result = await sdk.backend.getAllAnalyses();
    if (result.kind === "Ok") {
      store.send({ type: "Success", analyses: result.value });
    } else {
      store.send({ type: "Error", error: result.error });
    }
  };

  const clearCache = async () => {
    const result = await sdk.backend.clearCache();
    if (result.kind === "Ok") {
      store.send({ type: "Clear" });
    } else {
      sdk.window.showToast("Failed to clear cache", { variant: "error" });
    }
  };

  const getAnalysis = async (
    requestId: string,
  ): Promise<AnalysisResult | undefined> => {
    const result = await sdk.backend.getAnalysis(requestId);
    if (result.kind === "Ok") return result.value;
    return undefined;
  };

  return { summary, initialize, loadAnalyses, clearCache, getAnalysis };
});
