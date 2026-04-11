<script setup lang="ts">
import { storeToRefs } from "pinia";
import { onMounted } from "vue";

import BypassEntry from "./BypassEntry.vue";

import { useBypassData } from "@/composables/useBypassData";

const bypassStore = useBypassData();
const { loading, searchQuery, filteredRecords } = storeToRefs(bypassStore);

onMounted(() => {
  void bypassStore.loadRecords();
});
</script>

<template>
  <div class="h-full flex flex-col min-h-0">
    <div v-if="loading" class="flex-1 flex items-center justify-center">
      <span class="text-sm text-surface-400">Loading bypass records...</span>
    </div>

    <div
      v-else-if="filteredRecords.length > 0"
      class="flex-1 min-h-0 overflow-auto p-2"
    >
      <div class="flex flex-col gap-1.5">
        <BypassEntry
          v-for="record in filteredRecords"
          :key="record.id"
          :record="record"
        />
      </div>
    </div>

    <div
      v-else
      class="flex-1 flex items-center justify-center flex-col gap-3 text-center"
    >
      <i class="fas fa-magnifying-glass text-surface-500 text-4xl" />
      <p class="text-surface-400 text-sm">
        {{
          searchQuery.trim() !== ""
            ? `No results for "${searchQuery}"`
            : "No bypass records loaded"
        }}
      </p>
    </div>
  </div>
</template>
