<script setup lang="ts">
import { storeToRefs } from "pinia";
import Button from "primevue/button";
import Card from "primevue/card";
import InputSwitch from "primevue/inputswitch";
import SplitButton from "primevue/splitbutton";
import type { SeverityLevel } from "shared";
import { computed, ref } from "vue";

import { AnalysesTable } from "./AnalysesTable";
import { GettingStarted } from "./GettingStarted";
import { StatsBar } from "./StatsBar";

import { useExportDownload } from "@/composables/useExportDownload";
import { useAnalysesService } from "@/services/analyses";
import { useSettingsService } from "@/services/settings";
import { useAnalysesStore } from "@/stores/analyses";

const analysesStore = useAnalysesStore();
const analysesService = useAnalysesService();
const settingsService = useSettingsService();
const { scopeEnabled, findingsEnabled } = storeToRefs(settingsService);
const { downloadAsJson, downloadAsCsv } = useExportDownload();
const refreshing = ref(false);

const state = computed(() => analysesStore.state);

const analyses = computed(() => {
  const s = state.value;
  return s.type === "Success" ? s.analyses : [];
});

const summary = computed(() => {
  const a = analyses.value;
  const allFindings = a.flatMap((x) => x.findings);
  const severityCounts: Record<SeverityLevel, number> = {
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  const checkIdCounts: Record<string, number> = {};
  for (const f of allFindings) {
    severityCounts[f.severity]++;
    checkIdCounts[f.checkId] = (checkIdCounts[f.checkId] ?? 0) + 1;
  }
  const lastAnalyzedAt = a.reduce<Date | undefined>((latest, x) => {
    if (latest === undefined) return x.analyzedAt;
    return x.analyzedAt > latest ? x.analyzedAt : latest;
  }, undefined);
  return {
    totalAnalyses: a.length,
    totalFindings: allFindings.length,
    severityCounts,
    checkIdCounts,
    lastAnalyzedAt,
  };
});

const exportItems = [
  { label: "Export CSV", command: () => void downloadAsCsv() },
];

const onRefresh = async () => {
  refreshing.value = true;
  try {
    await analysesService.loadAnalyses();
  } finally {
    refreshing.value = false;
  }
};
</script>

<template>
  <div class="h-full flex flex-col gap-1 min-h-0">
    <Card
      class="shrink-0"
      :pt="{ body: { class: 'p-0' }, content: { class: 'p-0' } }"
    >
      <template #content>
        <div
          class="flex items-center justify-between px-4 py-2 overflow-hidden"
        >
          <StatsBar :summary="summary" class="w-1/2" />
          <div class="flex items-center gap-3">
            <div class="flex items-center gap-1.5">
              <span class="text-xs text-surface-400">Scope</span>
              <InputSwitch
                :model-value="scopeEnabled"
                @update:model-value="settingsService.updateScope($event)"
              />
            </div>
            <div class="flex items-center gap-1.5">
              <span class="text-xs text-surface-400">Findings</span>
              <InputSwitch
                :model-value="findingsEnabled"
                @update:model-value="settingsService.updateFindings($event)"
              />
            </div>
            <Button
              icon="fas fa-sync"
              severity="secondary"
              outlined
              size="small"
              :loading="refreshing"
              @mousedown="onRefresh"
            />
            <SplitButton
              label="Export JSON"
              icon="fas fa-download"
              size="small"
              :model="exportItems"
              @click="downloadAsJson()"
            />
            <Button
              icon="fas fa-trash"
              severity="danger"
              outlined
              size="small"
              @mousedown="analysesService.clearCache()"
            />
          </div>
        </div>
      </template>
    </Card>

    <div class="flex-1 min-h-0">
      <AnalysesTable v-if="analyses.length > 0" :analyses="analyses" />
      <div
        v-else-if="state.type === 'Error'"
        class="h-full flex items-center justify-center flex-col gap-3 text-center"
      >
        <i class="fas fa-exclamation-triangle text-red-400 text-4xl" />
        <p class="text-surface-400 text-sm">Failed to load analyses</p>
      </div>
      <div
        v-else-if="state.type === 'Loading'"
        class="h-full flex items-center justify-center"
      >
        <span class="text-surface-400 text-sm">Loading analyses...</span>
      </div>
      <GettingStarted v-else />
    </div>
  </div>
</template>
