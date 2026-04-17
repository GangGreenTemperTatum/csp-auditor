import { defineStore } from "pinia";
import type { BypassRecord, CuratedBypass } from "shared";
import { computed, ref } from "vue";

import { getBypassesForCheck } from "@/data/bypassPayloads";
import { useSDK } from "@/plugins/sdk";

export const useBypassData = defineStore("bypass-data", () => {
  const sdk = useSDK();
  const records = ref<BypassRecord[]>([]);
  const loading = ref(false);
  const searchQuery = ref("");

  const loadRecords = async () => {
    loading.value = true;
    try {
      const result = await sdk.backend.getBypassRecords();
      if (result.kind === "Ok") {
        records.value = result.value;
      } else {
        records.value = [];
        sdk.window.showToast("Failed to load bypass records", {
          variant: "error",
        });
      }
    } finally {
      loading.value = false;
    }
  };

  const filteredRecords = computed(() => {
    if (searchQuery.value.trim() === "") return records.value;

    const query = searchQuery.value.toLowerCase();
    return records.value.filter(
      (r) =>
        r.domain.toLowerCase().includes(query) ||
        r.technique.toLowerCase().includes(query) ||
        r.code.toLowerCase().includes(query),
    );
  });

  const findBypassesForCheck = (checkId: string): CuratedBypass[] => {
    return getBypassesForCheck(checkId, records.value);
  };

  return {
    records,
    loading,
    searchQuery,
    filteredRecords,
    loadRecords,
    findBypassesForCheck,
  };
});
