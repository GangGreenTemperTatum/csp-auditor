<script setup lang="ts">
import Column from "primevue/column";
import DataTable from "primevue/datatable";
import type { AnalysisResult } from "shared";
import { computed, ref } from "vue";

import ExpandedRow from "./ExpandedRow.vue";

import { extractHostAndPath, formatDate } from "@/utils/formatting";

const props = defineProps<{ analyses: AnalysisResult[] }>();
const expandedRows = ref<Record<string, boolean>>({});

type TableRow = AnalysisResult & {
  host: string;
  path: string;
  findingsCount: number;
  policiesCount: number;
};

const rows = computed((): TableRow[] =>
  props.analyses.map((a) => {
    const { host, path } = extractHostAndPath(a);
    return {
      ...a,
      host,
      path,
      findingsCount: a.findings.length,
      policiesCount: a.policies.length,
    };
  }),
);

function r(data: unknown): TableRow {
  return data as TableRow;
}
</script>

<template>
  <DataTable
    v-model:expanded-rows="expandedRows"
    :value="rows"
    scrollable
    striped-rows
    scroll-height="flex"
    size="small"
    expandable-rows
    removable-sort
    data-key="requestId"
    table-style="table-layout: fixed; width: 100%"
    class="h-full"
  >
    <Column :expander="true" style="width: 3%" />
    <Column field="requestId" sortable style="width: 7%">
      <template #header><span class="text-xs">ID</span></template>
      <template #body="slotProps">
        <span class="text-xs text-surface-400">{{
          r(slotProps.data).requestId
        }}</span>
      </template>
    </Column>
    <Column field="analyzedAt" sortable style="width: 15%">
      <template #header><span class="text-xs">Timestamp</span></template>
      <template #body="slotProps">
        <span class="text-xs text-surface-400">{{
          formatDate(r(slotProps.data).analyzedAt)
        }}</span>
      </template>
    </Column>
    <Column field="host" sortable style="width: 18%">
      <template #header><span class="text-xs">Host</span></template>
      <template #body="slotProps">
        <span class="text-xs font-medium text-surface-200 block truncate">{{
          r(slotProps.data).host
        }}</span>
      </template>
    </Column>
    <Column field="path" sortable style="width: 37%">
      <template #header><span class="text-xs">Path</span></template>
      <template #body="slotProps">
        <span class="text-xs text-surface-400 block truncate">{{
          r(slotProps.data).path
        }}</span>
      </template>
    </Column>
    <Column field="findingsCount" sortable style="width: 10%">
      <template #header><span class="text-xs">Findings</span></template>
      <template #body="slotProps">
        <span class="text-xs font-medium">{{
          r(slotProps.data).findingsCount
        }}</span>
      </template>
    </Column>
    <Column field="policiesCount" sortable style="width: 10%">
      <template #header><span class="text-xs">Policies</span></template>
      <template #body="slotProps">
        <span class="text-xs font-medium">{{
          r(slotProps.data).policiesCount
        }}</span>
      </template>
    </Column>

    <template #expansion="slotProps">
      <ExpandedRow :analysis="r(slotProps.data)" />
    </template>

    <template #empty>
      <div class="text-center text-surface-500 py-8 text-sm">
        No analyses found
      </div>
    </template>
  </DataTable>
</template>
