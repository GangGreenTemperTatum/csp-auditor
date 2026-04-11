import { defineStore, storeToRefs } from "pinia";
import type { ConfigurableCheckId } from "shared";
import { computed } from "vue";

import { useSettingsStore } from "@/stores/settings";

export const useSettingsService = defineStore("services.settings", () => {
  const store = useSettingsStore();
  const { scopeEnabled, findingsEnabled, checkSettings } = storeToRefs(store);

  const enabledCount = computed(
    () => Object.values(checkSettings.value).filter((c) => c.enabled).length,
  );

  const totalCount = computed(() => Object.keys(checkSettings.value).length);

  const initialize = () => store.initialize();
  const loadAll = () => store.loadAll();
  const updateScope = (enabled: boolean) => store.updateScope(enabled);
  const updateFindings = (enabled: boolean) => store.updateFindings(enabled);
  const updateSingleCheck = (checkId: ConfigurableCheckId, enabled: boolean) =>
    store.updateSingleCheck(checkId, enabled);
  const setAllChecks = (enabled: boolean) => store.setAllChecks(enabled);
  const setRecommendedMode = () => store.setRecommendedMode();
  const setLightMode = () => store.setLightMode();

  return {
    scopeEnabled,
    findingsEnabled,
    checkSettings,
    enabledCount,
    totalCount,
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
