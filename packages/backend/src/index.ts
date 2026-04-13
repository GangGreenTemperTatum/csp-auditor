import type { DefineAPI, DefineEvents, SDK } from "caido:plugin";
import type { BackendEventMap } from "shared";

import {
  apiClearCache,
  apiExportFindings,
  apiGetAllAnalyses,
  apiGetAnalysis,
  apiGetBypassRecords,
  apiGetCheckSettings,
  apiGetFindingsEnabled,
  apiGetScopeEnabled,
  apiGetSummary,
  apiSetCheckSettings,
  apiSetFindingsEnabled,
  apiSetScopeEnabled,
  apiUpdateSingleCheck,
} from "./api";
import { extractCspHeaders } from "./engine";
import { setSDK } from "./sdk";
import { getScopeEnabled, processResponse } from "./services";
import type { BackendEvents as BackendEventsType } from "./types";

export type API = DefineAPI<{
  getAllAnalyses: typeof apiGetAllAnalyses;
  getAnalysis: typeof apiGetAnalysis;
  getSummary: typeof apiGetSummary;
  clearCache: typeof apiClearCache;
  getScopeEnabled: typeof apiGetScopeEnabled;
  setScopeEnabled: typeof apiSetScopeEnabled;
  getFindingsEnabled: typeof apiGetFindingsEnabled;
  setFindingsEnabled: typeof apiSetFindingsEnabled;
  getCheckSettings: typeof apiGetCheckSettings;
  setCheckSettings: typeof apiSetCheckSettings;
  updateSingleCheck: typeof apiUpdateSingleCheck;
  exportFindings: typeof apiExportFindings;
  getBypassRecords: typeof apiGetBypassRecords;
}>;

export type Events = DefineEvents<BackendEventMap>;

export function init(sdk: SDK<API, BackendEventsType>) {
  setSDK(sdk);

  sdk.api.register("getAllAnalyses", apiGetAllAnalyses);
  sdk.api.register("getAnalysis", apiGetAnalysis);
  sdk.api.register("getSummary", apiGetSummary);
  sdk.api.register("clearCache", apiClearCache);
  sdk.api.register("getScopeEnabled", apiGetScopeEnabled);
  sdk.api.register("setScopeEnabled", apiSetScopeEnabled);
  sdk.api.register("getFindingsEnabled", apiGetFindingsEnabled);
  sdk.api.register("setFindingsEnabled", apiSetFindingsEnabled);
  sdk.api.register("getCheckSettings", apiGetCheckSettings);
  sdk.api.register("setCheckSettings", apiSetCheckSettings);
  sdk.api.register("updateSingleCheck", apiUpdateSingleCheck);
  sdk.api.register("exportFindings", apiExportFindings);
  sdk.api.register("getBypassRecords", apiGetBypassRecords);

  sdk.events.onInterceptResponse(async (_sdk, request, response) => {
    try {
      const headers = response.getHeaders();
      const cspHeaders = extractCspHeaders(headers);
      if (cspHeaders.length === 0) return;

      if (getScopeEnabled() && !_sdk.requests.inScope(request)) return;

      await processResponse(
        {
          id: request.getId(),
          host: request.getHost(),
          path: request.getPath(),
        },
        { headers },
        request,
      );
    } catch (error) {
      sdk.console.error(
        `CSP analysis failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  });

  sdk.console.log("CSP Auditor v2.0 initialized");
}
