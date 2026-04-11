<script setup lang="ts">
import Badge from "primevue/badge";
import Button from "primevue/button";
import type { ParsedPolicy } from "shared";

import { useClipboard } from "@/composables/useClipboard";

const props = defineProps<{ policy: ParsedPolicy }>();
const { copyToClipboard } = useClipboard();
</script>

<template>
  <div class="border border-surface-700 rounded-lg p-3 bg-surface-800">
    <div class="flex items-center justify-between mb-2">
      <span class="text-sm font-medium text-surface-200">{{
        props.policy.headerName
      }}</span>
      <div class="flex gap-2 items-center">
        <Button
          icon="fas fa-copy"
          size="small"
          severity="secondary"
          text
          @mousedown="
            copyToClipboard(props.policy.headerValue, 'Policy copied')
          "
        />
        <Badge
          v-if="props.policy.isReportOnly"
          value="Report Only"
          severity="info"
          class="text-xs"
        />
        <Badge
          v-if="props.policy.isDeprecated"
          value="Deprecated"
          severity="warning"
          class="text-xs"
        />
      </div>
    </div>
    <div class="bg-surface-900 p-2 rounded">
      <code
        class="text-xs font-mono text-surface-300 break-all whitespace-pre-wrap"
      >
        {{ props.policy.headerValue }}
      </code>
    </div>
  </div>
</template>
