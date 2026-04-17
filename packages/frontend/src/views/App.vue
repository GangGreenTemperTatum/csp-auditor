<script setup lang="ts">
import Button from "primevue/button";
import MenuBar from "primevue/menubar";
import { onMounted } from "vue";

import { VulnerabilityModal } from "@/components/VulnerabilityModal";
import { usePageNavigation } from "@/composables/usePageNavigation";
import { useAnalysesService } from "@/services/analyses";
import { useSettingsService } from "@/services/settings";

const { navItems, component } = usePageNavigation();
const analysesService = useAnalysesService();
const settingsService = useSettingsService();

onMounted(async () => {
  await settingsService.initialize();
  await analysesService.initialize();
});
</script>

<template>
  <div class="h-full flex flex-col gap-1">
    <MenuBar :model="navItems" class="h-12">
      <template #item="{ item }">
        <Button
          :label="item.label"
          :severity="item.isActive?.() ? 'secondary' : 'contrast'"
          :outlined="item.isActive?.()"
          :text="!item.isActive?.()"
          size="small"
          @mousedown="item.command"
        />
      </template>
    </MenuBar>

    <div class="flex-1 min-h-0">
      <component :is="component" />
    </div>

    <VulnerabilityModal />
  </div>
</template>
