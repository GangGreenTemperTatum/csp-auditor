import { createPinia, setActivePinia } from "pinia";
import type { AnalysisResult } from "shared";

const mockBackend = {
  getAllAnalyses: vi.fn(),
  getAnalysis: vi.fn(),
  getSummary: vi.fn(),
  clearCache: vi.fn(),
  onEvent: vi.fn(),
};

const mockWindow = {
  showToast: vi.fn(),
};

vi.mock("@/plugins/sdk", () => ({
  useSDK: () => ({ backend: mockBackend, window: mockWindow }),
}));

const { useAnalysesService } = await import("./analyses");
const { useAnalysesStore } = await import("@/stores/analyses");

function fakeAnalysis(overrides?: Partial<AnalysisResult>): AnalysisResult {
  return {
    requestId: "req-1",
    policies: [],
    findings: [
      {
        id: "f-1",
        checkId: "script-wildcard",
        severity: "high",
        directive: "script-src",
        value: "*",
        description: "test",
        remediation: "fix",
        requestId: "req-1",
      },
    ],
    analyzedAt: new Date("2025-01-01"),
    ...overrides,
  };
}

describe("useAnalysesService", () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    vi.clearAllMocks();
  });

  describe("initialize", () => {
    it("loads analyses and registers event listener", async () => {
      mockBackend.getAllAnalyses.mockResolvedValue({
        kind: "Ok",
        value: [fakeAnalysis()],
      });

      const service = useAnalysesService();
      await service.initialize();

      expect(mockBackend.getAllAnalyses).toHaveBeenCalledOnce();
      expect(mockBackend.onEvent).toHaveBeenCalledWith(
        "analysisUpdated",
        expect.any(Function),
      );
      expect(useAnalysesStore().state.type).toBe("Success");
    });

    it("sets error state when backend fails", async () => {
      mockBackend.getAllAnalyses.mockResolvedValue({
        kind: "Error",
        error: "network failure",
      });

      const service = useAnalysesService();
      await service.initialize();

      expect(useAnalysesStore().state.type).toBe("Error");
    });

    it("does not register duplicate event listeners", async () => {
      mockBackend.getAllAnalyses.mockResolvedValue({ kind: "Ok", value: [] });

      const service = useAnalysesService();
      await service.initialize();
      await service.initialize();

      expect(mockBackend.onEvent).toHaveBeenCalledTimes(1);
    });
  });

  describe("loadAnalyses", () => {
    it("updates state with analyses on success", async () => {
      const analyses = [fakeAnalysis(), fakeAnalysis({ requestId: "req-2" })];
      mockBackend.getAllAnalyses.mockResolvedValue({
        kind: "Ok",
        value: analyses,
      });

      const service = useAnalysesService();
      await service.loadAnalyses();

      const s = useAnalysesStore().state;
      expect(s.type).toBe("Success");
      if (s.type === "Success") {
        expect(s.analyses).toHaveLength(2);
      }
    });
  });

  describe("clearCache", () => {
    it("clears state on success", async () => {
      mockBackend.getAllAnalyses.mockResolvedValue({
        kind: "Ok",
        value: [fakeAnalysis()],
      });
      mockBackend.clearCache.mockResolvedValue({
        kind: "Ok",
        value: undefined,
      });

      const service = useAnalysesService();
      await service.loadAnalyses();
      await service.clearCache();

      expect(useAnalysesStore().state.type).toBe("Idle");
    });

    it("shows error toast on failure", async () => {
      mockBackend.clearCache.mockResolvedValue({
        kind: "Error",
        error: "failed",
      });

      const service = useAnalysesService();
      await service.clearCache();

      expect(mockWindow.showToast).toHaveBeenCalledWith(
        "Failed to clear cache",
        { variant: "error" },
      );
    });
  });

  describe("summary", () => {
    it("computes correct severity counts", async () => {
      const analyses = [
        fakeAnalysis({
          findings: [
            {
              id: "f-1",
              checkId: "script-wildcard",
              severity: "high",
              directive: "script-src",
              value: "*",
              description: "a",
              remediation: "b",
              requestId: "req-1",
            },
            {
              id: "f-2",
              checkId: "style-wildcard",
              severity: "low",
              directive: "style-src",
              value: "*",
              description: "c",
              remediation: "d",
              requestId: "req-1",
            },
          ],
        }),
      ];
      mockBackend.getAllAnalyses.mockResolvedValue({
        kind: "Ok",
        value: analyses,
      });

      const service = useAnalysesService();
      await service.loadAnalyses();

      expect(service.summary.totalFindings).toBe(2);
      expect(service.summary.severityCounts.high).toBe(1);
      expect(service.summary.severityCounts.low).toBe(1);
    });

    it("finds the most recent analyzedAt", async () => {
      const analyses = [
        fakeAnalysis({
          requestId: "req-1",
          analyzedAt: new Date("2025-01-01"),
        }),
        fakeAnalysis({
          requestId: "req-2",
          analyzedAt: new Date("2025-06-15"),
        }),
        fakeAnalysis({
          requestId: "req-3",
          analyzedAt: new Date("2025-03-10"),
        }),
      ];
      mockBackend.getAllAnalyses.mockResolvedValue({
        kind: "Ok",
        value: analyses,
      });

      const service = useAnalysesService();
      await service.loadAnalyses();

      expect(service.summary.lastAnalyzedAt).toEqual(new Date("2025-06-15"));
    });
  });

  describe("getAnalysis", () => {
    it("returns analysis on success", async () => {
      const analysis = fakeAnalysis();
      mockBackend.getAnalysis.mockResolvedValue({
        kind: "Ok",
        value: analysis,
      });

      const service = useAnalysesService();
      const result = await service.getAnalysis("req-1");

      expect(result).toBeDefined();
      expect(result?.requestId).toBe("req-1");
    });

    it("returns undefined on error", async () => {
      mockBackend.getAnalysis.mockResolvedValue({
        kind: "Error",
        error: "not found",
      });

      const service = useAnalysesService();
      const result = await service.getAnalysis("req-999");

      expect(result).toBeUndefined();
    });
  });
});
