<script setup lang="ts">
import { storeToRefs } from "pinia";
import Card from "primevue/card";
import IconField from "primevue/iconfield";
import InputIcon from "primevue/inputicon";
import InputText from "primevue/inputtext";

import { DatabasePage } from "@/components/Database";
import { useBypassData } from "@/composables/useBypassData";

const bypassStore = useBypassData();
const { searchQuery, records } = storeToRefs(bypassStore);
</script>

<template>
  <div class="h-full flex flex-col gap-1 min-h-0">
    <Card
      class="shrink-0"
      :pt="{ body: { class: 'p-0' }, content: { class: 'p-0' } }"
    >
      <template #content>
        <div class="flex justify-between items-center px-4 py-3 gap-4">
          <div class="flex-1">
            <h2 class="text-lg font-semibold">CSP Bypass Database</h2>
            <p class="text-sm text-surface-400">
              {{ records.length }} bypass techniques from security research
            </p>
          </div>
          <IconField>
            <InputIcon class="fas fa-magnifying-glass" />
            <InputText
              v-model="searchQuery"
              placeholder="Search..."
              class="w-64"
            />
          </IconField>
        </div>
      </template>
    </Card>
    <div class="flex-1 min-h-0">
      <DatabasePage />
    </div>
  </div>
</template>
