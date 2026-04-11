import { createPinia, setActivePinia } from "pinia";

const mockBackend = {
  getScopeEnabled: vi.fn(),
  setScopeEnabled: vi.fn(),
  getFindingsEnabled: vi.fn(),
  setFindingsEnabled: vi.fn(),
  getCheckSettings: vi.fn(),
  setCheckSettings: vi.fn(),
  updateSingleCheck: vi.fn(),
};

vi.mock("@/plugins/sdk", () => ({
  useSDK: () => ({ backend: mockBackend }),
}));

const { useSettingsService } = await import("./settings");

describe("useSettingsService", () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    vi.clearAllMocks();
  });

  describe("initialize", () => {
    it("loads settings from backend", async () => {
      mockBackend.getScopeEnabled.mockResolvedValue({
        kind: "Ok",
        value: false,
      });
      mockBackend.getFindingsEnabled.mockResolvedValue({
        kind: "Ok",
        value: true,
      });
      mockBackend.getCheckSettings.mockResolvedValue({
        kind: "Ok",
        value: { "script-wildcard": false },
      });

      const service = useSettingsService();
      await service.initialize();

      expect(service.scopeEnabled).toBe(false);
      expect(service.findingsEnabled).toBe(true);
    });

    it("retries on failure", async () => {
      mockBackend.getScopeEnabled.mockRejectedValueOnce(new Error("network"));
      mockBackend.getScopeEnabled.mockResolvedValue({
        kind: "Ok",
        value: true,
      });
      mockBackend.getFindingsEnabled.mockResolvedValue({
        kind: "Ok",
        value: false,
      });
      mockBackend.getCheckSettings.mockResolvedValue({ kind: "Ok", value: {} });

      const service = useSettingsService();
      await service.initialize();
      await service.initialize();

      expect(mockBackend.getScopeEnabled).toHaveBeenCalledTimes(2);
    });
  });

  describe("updateScope", () => {
    it("updates local state on success", async () => {
      mockBackend.setScopeEnabled.mockResolvedValue({
        kind: "Ok",
        value: undefined,
      });

      const service = useSettingsService();
      await service.updateScope(false);

      expect(service.scopeEnabled).toBe(false);
      expect(mockBackend.setScopeEnabled).toHaveBeenCalledWith(false);
    });

    it("does not update local state on error", async () => {
      mockBackend.setScopeEnabled.mockResolvedValue({
        kind: "Error",
        error: "failed",
      });

      const service = useSettingsService();
      await service.updateScope(false);

      expect(service.scopeEnabled).toBe(true);
    });
  });

  describe("updateFindings", () => {
    it("updates local state on success", async () => {
      mockBackend.setFindingsEnabled.mockResolvedValue({
        kind: "Ok",
        value: undefined,
      });

      const service = useSettingsService();
      await service.updateFindings(true);

      expect(service.findingsEnabled).toBe(true);
    });

    it("does not update local state on error", async () => {
      mockBackend.setFindingsEnabled.mockResolvedValue({
        kind: "Error",
        error: "failed",
      });

      const service = useSettingsService();
      await service.updateFindings(true);

      expect(service.findingsEnabled).toBe(false);
    });
  });

  describe("updateSingleCheck", () => {
    it("updates check state on success", async () => {
      mockBackend.updateSingleCheck.mockResolvedValue({
        kind: "Ok",
        value: undefined,
      });

      const service = useSettingsService();
      const wasBefore = service.checkSettings["script-wildcard"]?.enabled;
      await service.updateSingleCheck("script-wildcard", false);

      expect(wasBefore).toBe(true);
      expect(service.checkSettings["script-wildcard"]?.enabled).toBe(false);
    });
  });

  describe("setAllChecks", () => {
    it("disables all checks on success", async () => {
      mockBackend.setCheckSettings.mockResolvedValue({
        kind: "Ok",
        value: undefined,
      });

      const service = useSettingsService();
      await service.setAllChecks(false);

      const allDisabled = Object.values(service.checkSettings).every(
        (c) => !c.enabled,
      );
      expect(allDisabled).toBe(true);
    });

    it("does not update on error", async () => {
      mockBackend.setCheckSettings.mockResolvedValue({
        kind: "Error",
        error: "failed",
      });

      const service = useSettingsService();
      await service.setAllChecks(false);

      const someEnabled = Object.values(service.checkSettings).some(
        (c) => c.enabled,
      );
      expect(someEnabled).toBe(true);
    });
  });

  describe("presets", () => {
    it("setRecommendedMode enables high and medium only", async () => {
      mockBackend.setCheckSettings.mockResolvedValue({
        kind: "Ok",
        value: undefined,
      });

      const service = useSettingsService();
      await service.setRecommendedMode();

      for (const check of Object.values(service.checkSettings)) {
        if (check.severity === "high" || check.severity === "medium") {
          expect(check.enabled).toBe(true);
        } else {
          expect(check.enabled).toBe(false);
        }
      }
    });

    it("setLightMode enables high and Critical only", async () => {
      mockBackend.setCheckSettings.mockResolvedValue({
        kind: "Ok",
        value: undefined,
      });

      const service = useSettingsService();
      await service.setLightMode();

      for (const check of Object.values(service.checkSettings)) {
        if (check.severity === "high" || check.category === "Critical") {
          expect(check.enabled).toBe(true);
        } else {
          expect(check.enabled).toBe(false);
        }
      }
    });
  });

  describe("computed counts", () => {
    it("enabledCount reflects current state", async () => {
      mockBackend.setCheckSettings.mockResolvedValue({
        kind: "Ok",
        value: undefined,
      });

      const service = useSettingsService();
      const totalBefore = service.totalCount;
      expect(service.enabledCount).toBe(totalBefore);

      await service.setAllChecks(false);
      expect(service.enabledCount).toBe(0);
    });
  });
});
