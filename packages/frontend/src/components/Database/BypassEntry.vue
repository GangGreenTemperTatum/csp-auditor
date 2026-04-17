<script setup lang="ts">
import Button from "primevue/button";
import Tag from "primevue/tag";
import type { BypassRecord } from "shared";

import { useClipboard } from "@/composables/useClipboard";
import { getTechniqueColor } from "@/utils/technique";

const props = defineProps<{ record: BypassRecord }>();
const { copyToClipboard } = useClipboard();
</script>

<template>
  <div
    class="bg-surface-900 rounded p-2.5 cursor-pointer transition-colors border border-transparent hover:border-surface-600"
    @click="copyToClipboard(props.record.code, 'Payload copied')"
  >
    <div class="flex items-center justify-between mb-1.5">
      <div class="flex items-center gap-2">
        <span class="text-xs font-mono text-blue-400">{{
          props.record.domain
        }}</span>
        <Tag
          :value="props.record.technique"
          :severity="getTechniqueColor(props.record.technique)"
          class="!text-[10px] !px-1.5 !py-0"
        />
      </div>
      <Button
        icon="fas fa-copy"
        size="small"
        severity="secondary"
        text
        class="!w-6 !h-6"
        @click.stop="copyToClipboard(props.record.code, 'Payload copied')"
      />
    </div>
    <div
      class="text-green-400 px-2 py-1 text-[11px] font-mono overflow-x-auto whitespace-nowrap"
    >
      {{ props.record.code }}
    </div>
  </div>
</template>
