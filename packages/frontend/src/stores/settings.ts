import { defineStore } from "pinia";
import { DEFAULT_CHECK_DEFINITIONS } from "shared";
import type { CheckDefinition, ConfigurableCheckId } from "shared";
import { ref } from "vue";

import { useSDK } from "@/plugins/sdk";

type CheckSettingsMap = Record<string, { enabled: boolean } & CheckDefinition>;

function buildInitialChecks(): CheckSettingsMap {
  const result: CheckSettingsMap = {};
  for (const [id, def] of Object.entries(DEFAULT_CHECK_DEFINITIONS)) {
    result[id] = { enabled: true, ...def };
  }
  return result;
}

export const useSettingsStore = defineStore("stores.settings", () => {
  const sdk = useSDK();
  const scopeEnabled = ref(true);
  const findingsEnabled = ref(false);
  const checkSettings = ref<CheckSettingsMap>(buildInitialChecks());
  let initPromise: Promise<void> | undefined;

  async function initialize() {
    if (initPromise !== undefined) return initPromise;
    initPromise = loadAll().catch(() => {
      initPromise = undefined;
    });
    await initPromise;
  }

  async function loadAll() {
    const scopeResult = await sdk.backend.getScopeEnabled();
    if (scopeResult.kind === "Ok") scopeEnabled.value = scopeResult.value;

    const findingsResult = await sdk.backend.getFindingsEnabled();
    if (findingsResult.kind === "Ok")
      findingsEnabled.value = findingsResult.value;

    const checksResult = await sdk.backend.getCheckSettings();
    if (checksResult.kind === "Ok") {
      for (const [id, enabled] of Object.entries(checksResult.value)) {
        if (checkSettings.value[id] !== undefined) {
          checkSettings.value[id].enabled = enabled;
        }
      }
    }
  }

  async function updateScope(enabled: boolean) {
    const result = await sdk.backend.setScopeEnabled(enabled);
    if (result.kind === "Ok") scopeEnabled.value = enabled;
  }

  async function updateFindings(enabled: boolean) {
    const result = await sdk.backend.setFindingsEnabled(enabled);
    if (result.kind === "Ok") findingsEnabled.value = enabled;
  }

  async function updateSingleCheck(
    checkId: ConfigurableCheckId,
    enabled: boolean,
  ) {
    const result = await sdk.backend.updateSingleCheck(checkId, enabled);
    if (result.kind === "Ok" && checkSettings.value[checkId] !== undefined) {
      checkSettings.value[checkId].enabled = enabled;
    }
  }

  async function setAllChecks(enabled: boolean) {
    const settingsMap: Record<string, boolean> = {};
    for (const id of Object.keys(checkSettings.value)) {
      settingsMap[id] = enabled;
    }
    const result = await sdk.backend.setCheckSettings(settingsMap);
    if (result.kind === "Ok") {
      for (const id of Object.keys(checkSettings.value)) {
        checkSettings.value[id]!.enabled = enabled;
      }
    }
  }

  async function setRecommendedMode() {
    const settingsMap: Record<string, boolean> = {};
    for (const [id, check] of Object.entries(checkSettings.value)) {
      settingsMap[id] =
        check.severity === "high" || check.severity === "medium";
    }
    const result = await sdk.backend.setCheckSettings(settingsMap);
    if (result.kind === "Ok") {
      for (const [id, check] of Object.entries(checkSettings.value)) {
        check.enabled = settingsMap[id]!;
      }
    }
  }

  async function setLightMode() {
    const settingsMap: Record<string, boolean> = {};
    for (const [id, check] of Object.entries(checkSettings.value)) {
      settingsMap[id] =
        check.severity === "high" || check.category === "Critical";
    }
    const result = await sdk.backend.setCheckSettings(settingsMap);
    if (result.kind === "Ok") {
      for (const [id, check] of Object.entries(checkSettings.value)) {
        check.enabled = settingsMap[id]!;
      }
    }
  }

  return {
    scopeEnabled,
    findingsEnabled,
    checkSettings,
    initialize,
    loadAll,
    updateScope,
    updateFindings,
    updateSingleCheck,
    setAllChecks,
    setRecommendedMode,
    setLightMode,
  };
});
