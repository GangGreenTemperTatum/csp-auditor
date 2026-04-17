<script setup lang="ts">
import type { AnalysisSummary } from "shared";

const props = defineProps<{ summary: AnalysisSummary }>();
</script>

<template>
  <div class="flex items-center justify-between text-xs">
    <div class="flex items-center gap-1">
      <span class="font-semibold text-blue-400">{{
        props.summary.totalAnalyses
      }}</span>
      <span class="text-surface-400">analyses</span>
    </div>
    <div class="flex items-center gap-1">
      <span class="font-semibold text-surface-200">{{
        props.summary.totalFindings
      }}</span>
      <span class="text-surface-400">findings</span>
    </div>
    <div class="flex items-center gap-1">
      <span class="font-semibold text-red-400">{{
        props.summary.severityCounts.high
      }}</span>
      <span class="text-surface-400">high</span>
    </div>
    <div class="flex items-center gap-1">
      <span class="font-semibold text-orange-400">{{
        props.summary.severityCounts.medium
      }}</span>
      <span class="text-surface-400">medium</span>
    </div>
    <div class="flex items-center gap-1">
      <span class="font-semibold text-yellow-400">{{
        props.summary.severityCounts.low
      }}</span>
      <span class="text-surface-400">low</span>
    </div>
  </div>
</template>
