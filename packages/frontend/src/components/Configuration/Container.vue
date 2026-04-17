<script setup lang="ts">
import { storeToRefs } from "pinia";
import Button from "primevue/button";
import Card from "primevue/card";
import Column from "primevue/column";
import DataTable from "primevue/datatable";
import IconField from "primevue/iconfield";
import InputIcon from "primevue/inputicon";
import InputText from "primevue/inputtext";
import ToggleSwitch from "primevue/toggleswitch";
import type { ConfigurableCheckId, SeverityLevel } from "shared";
import { computed, ref } from "vue";

import { useSettingsService } from "@/services/settings";
import { getSeverityBadgeStyle } from "@/utils/severity";

const settingsService = useSettingsService();
const { checkSettings } = storeToRefs(settingsService);
const search = ref("");

type CheckRow = {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: SeverityLevel;
  enabled: boolean;
};

const rows = computed((): CheckRow[] => {
  const items: CheckRow[] = [];
  for (const [id, check] of Object.entries(checkSettings.value)) {
    items.push({
      id,
      name: check.name,
      description: check.description,
      category: check.category,
      severity: check.severity,
      enabled: check.enabled,
    });
  }
  return items;
});

const filteredRows = computed(() => {
  if (search.value.trim() === "") return rows.value;
  const q = search.value.toLowerCase();
  return rows.value.filter(
    (row) =>
      row.name.toLowerCase().includes(q) ||
      row.id.toLowerCase().includes(q) ||
      row.description.toLowerCase().includes(q) ||
      row.category.toLowerCase().includes(q),
  );
});

const enabledCount = computed(
  () => rows.value.filter((row) => row.enabled).length,
);

const onToggle = (checkId: string, enabled: boolean) => {
  void settingsService.updateSingleCheck(
    checkId as ConfigurableCheckId,
    enabled,
  );
};

function r(data: unknown): CheckRow {
  return data as CheckRow;
}
</script>

<template>
  <div class="h-full flex flex-col min-h-0">
    <Card
      class="h-full"
      :pt="{
        root: { style: 'display: flex; flex-direction: column; height: 100%;' },
        body: { class: 'flex-1 p-0 flex flex-col min-h-0' },
        content: { class: 'flex-1 flex flex-col overflow-hidden min-h-0' },
      }"
    >
      <template #content>
        <div class="flex justify-between items-center p-4 gap-4">
          <div class="flex-1">
            <h3 class="text-lg font-semibold">Scan Configuration</h3>
            <p class="text-sm text-surface-300">
              {{ enabledCount }}/{{ rows.length }} vulnerability checks enabled
            </p>
          </div>
          <IconField>
            <InputIcon class="fas fa-magnifying-glass" />
            <InputText
              v-model="search"
              placeholder="Search checks"
              class="w-full"
            />
          </IconField>
        </div>

        <div class="flex-1 min-h-0">
          <DataTable
            :value="filteredRows"
            scrollable
            striped-rows
            scroll-height="flex"
            size="small"
            removable-sort
            data-key="id"
          >
            <Column field="name" sortable style="min-width: 12rem">
              <template #header><span class="text-xs">Name</span></template>
              <template #body="slotProps">
                <div>
                  <span class="text-sm font-medium">{{
                    r(slotProps.data).name
                  }}</span>
                  <span class="text-xs text-surface-500 ml-2">{{
                    r(slotProps.data).id
                  }}</span>
                </div>
              </template>
            </Column>
            <Column field="description" style="min-width: 14rem">
              <template #header
                ><span class="text-xs">Description</span></template
              >
              <template #body="slotProps">
                <span class="text-xs text-surface-400">{{
                  r(slotProps.data).description
                }}</span>
              </template>
            </Column>
            <Column field="category" sortable style="width: 10rem">
              <template #header><span class="text-xs">Category</span></template>
              <template #body="slotProps">
                <span class="text-xs text-surface-400">{{
                  r(slotProps.data).category
                }}</span>
              </template>
            </Column>
            <Column field="severity" sortable style="width: 7rem">
              <template #header><span class="text-xs">Severity</span></template>
              <template #body="slotProps">
                <span
                  class="inline-flex px-2 rounded-md text-xs font-mono border"
                  :class="getSeverityBadgeStyle(r(slotProps.data).severity)"
                >
                  {{ r(slotProps.data).severity }}
                </span>
              </template>
            </Column>
            <Column style="width: 5rem" class="text-center">
              <template #header><span class="text-xs">Enabled</span></template>
              <template #body="slotProps">
                <ToggleSwitch
                  :model-value="r(slotProps.data).enabled"
                  @update:model-value="onToggle(r(slotProps.data).id, $event)"
                />
              </template>
            </Column>

            <template #footer>
              <div class="flex items-center gap-2">
                <Button
                  label="Aggressive"
                  size="small"
                  severity="info"
                  outlined
                  @mousedown="settingsService.setAllChecks(true)"
                />
                <Button
                  label="Recommended"
                  size="small"
                  severity="info"
                  outlined
                  @mousedown="settingsService.setRecommendedMode()"
                />
                <Button
                  label="Light"
                  size="small"
                  severity="info"
                  outlined
                  @mousedown="settingsService.setLightMode()"
                />
                <Button
                  label="Disable All"
                  size="small"
                  severity="secondary"
                  outlined
                  @mousedown="settingsService.setAllChecks(false)"
                />
              </div>
            </template>

            <template #empty>
              <div class="text-center text-surface-500 py-8 text-sm">
                No checks match your search
              </div>
            </template>
          </DataTable>
        </div>
      </template>
    </Card>
  </div>
</template>
