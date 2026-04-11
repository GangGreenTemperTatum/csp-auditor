<script setup lang="ts">
import type { AnalysisResult, PolicyFinding } from "shared";

import PolicyCard from "./PolicyCard.vue";
import VulnerabilityCard from "./VulnerabilityCard.vue";

import { useVulnerabilityModal } from "@/composables/useVulnerabilityModal";

const props = defineProps<{ analysis: AnalysisResult }>();
const { openModal } = useVulnerabilityModal();

const onFindingClick = (finding: PolicyFinding) => {
  openModal(finding, props.analysis);
};
</script>

<template>
  <div class="p-4 space-y-4">
    <div v-if="props.analysis.findings.length > 0">
      <h4 class="text-sm font-semibold text-surface-300 mb-2">
        Findings ({{ props.analysis.findings.length }})
      </h4>
      <div class="flex flex-col gap-2">
        <VulnerabilityCard
          v-for="finding in props.analysis.findings"
          :key="finding.id"
          :finding="finding"
          @click="onFindingClick(finding)"
        />
      </div>
    </div>

    <div v-if="props.analysis.policies.length > 0">
      <h4 class="text-sm font-semibold text-surface-300 mb-2">
        Policies ({{ props.analysis.policies.length }})
      </h4>
      <div class="flex flex-col gap-2">
        <PolicyCard
          v-for="policy in props.analysis.policies"
          :key="policy.id"
          :policy="policy"
        />
      </div>
    </div>
  </div>
</template>
