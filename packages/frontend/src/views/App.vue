<script setup lang="ts">
import Badge from "primevue/badge";
import Button from "primevue/button";
import Card from "primevue/card";
import Divider from "primevue/divider";
import InputSwitch from "primevue/inputswitch";
import InputText from "primevue/inputtext";
import ProgressBar from "primevue/progressbar";
import TabPanel from "primevue/tabpanel";
import TabView from "primevue/tabview";
import Tag from "primevue/tag";
import { computed, onMounted, onUnmounted, ref, watch } from "vue";

import {
  type BypassPayload,
  getBypassesForVulnerability,
  getDifficultyColor,
} from "@/data/bypass-payloads";
import { useSDK } from "@/plugins/sdk";
import type { BypassEntry, CspAnalysisResult, CspStats } from "@/types";

const sdk = useSDK();

const stats = ref<CspStats>({
  totalAnalyses: 0,
  totalVulnerabilities: 0,
  severityStats: { high: 0, medium: 0, low: 0, info: 0 },
  typeStats: {},
  lastAnalyzed: null,
});

const allAnalyses = ref<CspAnalysisResult[]>([]);
const loading = ref(false);
const selectedAnalysis = ref<CspAnalysisResult | undefined>(undefined);

const currentPage = ref(1);
const itemsPerPage = ref(10);

const autoRefreshEnabled = ref(true);
const refreshInterval = ref<number | undefined>(undefined);
const REFRESH_INTERVAL_MS = 5000;

const respectScope = ref(true);
const createFindings = ref(false);

// Settings for CSP checks
const cspCheckSettings = ref({
  // Critical vulnerabilities
  "script-wildcard": {
    enabled: true,
    name: "Script Wildcard Sources",
    category: "Critical",
    severity: "high",
    description: "Detect wildcard (*) in script-src directive",
  },
  "script-unsafe-inline": {
    enabled: true,
    name: "Unsafe Inline Scripts",
    category: "Critical",
    severity: "high",
    description: "Detect unsafe-inline in script-src directive",
  },
  "script-unsafe-eval": {
    enabled: true,
    name: "Unsafe Eval",
    category: "Critical",
    severity: "high",
    description: "Detect unsafe-eval in script-src directive",
  },
  "script-data-uri": {
    enabled: true,
    name: "Data URI Scripts",
    category: "Critical",
    severity: "high",
    description: "Detect data: URIs in script-src directive",
  },
  "object-wildcard": {
    enabled: true,
    name: "Object Wildcard Sources",
    category: "Critical",
    severity: "high",
    description: "Detect wildcard (*) in object-src directive",
  },

  // Modern threats
  "jsonp-bypass-risk": {
    enabled: true,
    name: "JSONP Bypass Risk",
    category: "Modern Threats",
    severity: "high",
    description: "Detect domains that support JSONP callbacks",
  },
  "angularjs-bypass": {
    enabled: true,
    name: "AngularJS Template Injection",
    category: "Modern Threats",
    severity: "high",
    description: "Detect AngularJS template injection risks",
  },
  "ai-ml-host": {
    enabled: true,
    name: "AI/ML Service Integration",
    category: "Modern Threats",
    severity: "medium",
    description: "Detect AI/ML service endpoints",
  },
  "web3-host": {
    enabled: true,
    name: "Web3/Crypto Integration",
    category: "Modern Threats",
    severity: "medium",
    description: "Detect Web3/cryptocurrency endpoints",
  },
  "cdn-supply-chain": {
    enabled: true,
    name: "CDN Supply Chain Risk",
    category: "Modern Threats",
    severity: "medium",
    description: "Detect CDN endpoints with supply chain risks",
  },

  // Missing features
  "missing-trusted-types": {
    enabled: true,
    name: "Missing Trusted Types",
    category: "Missing Features",
    severity: "medium",
    description: "Check for missing trusted-types directive",
  },
  "missing-require-trusted-types": {
    enabled: true,
    name: "Missing Require Trusted Types",
    category: "Missing Features",
    severity: "medium",
    description: "Check for missing require-trusted-types-for directive",
  },
  "missing-essential-directive": {
    enabled: true,
    name: "Missing Essential Directives",
    category: "Missing Features",
    severity: "medium",
    description: "Check for missing essential CSP directives",
  },
  "permissive-base-uri": {
    enabled: true,
    name: "Permissive Base URI",
    category: "Policy Weaknesses",
    severity: "medium",
    description: "Check for overly permissive base-uri directive",
  },

  // Style-related
  "style-wildcard": {
    enabled: true,
    name: "Style Wildcard Sources",
    category: "Style Issues",
    severity: "low",
    description: "Detect wildcard (*) in style-src directive",
  },
  "style-unsafe-inline": {
    enabled: true,
    name: "Unsafe Inline Styles",
    category: "Style Issues",
    severity: "medium",
    description: "Detect unsafe-inline in style-src directive",
  },

  // Legacy/deprecated
  "deprecated-header": {
    enabled: true,
    name: "Deprecated CSP Headers",
    category: "Legacy Issues",
    severity: "medium",
    description: "Detect deprecated CSP header names",
  },
  "user-content-host": {
    enabled: true,
    name: "User Content Hosts",
    category: "Legacy Issues",
    severity: "high",
    description: "Detect domains that host user-uploaded content",
  },
  "vulnerable-js-host": {
    enabled: true,
    name: "Vulnerable JS Library Hosts",
    category: "Legacy Issues",
    severity: "high",
    description: "Detect domains with vulnerable JavaScript libraries",
  },

  // Advanced
  "nonce-unsafe-inline-conflict": {
    enabled: true,
    name: "Nonce/Unsafe-Inline Conflict",
    category: "Advanced",
    severity: "medium",
    description: "Detect nonce security weakened by unsafe-inline",
  },
});

const activeTab = ref(0);

// Modal state for vulnerability details
const showVulnerabilityModal = ref(false);
const selectedVulnerability = ref<unknown>(undefined);
const selectedAnalysisForModal = ref<CspAnalysisResult | undefined>(undefined);

// CSP Bypass data
const bypassEntries = ref<BypassEntry[]>([]);
const loadingBypasses = ref(false);
const bypassSearchQuery = ref("");

onMounted(async () => {
  await loadDashboardData();
  await loadScopeSettings();
  await loadCreateFindingsSettings();
  await loadCspCheckSettings();
  await loadBypassData();
  startAutoRefresh();
});

onUnmounted(() => {
  stopAutoRefresh();
});

// Watch for individual setting changes and save to backend
watch(
  cspCheckSettings,
  () => {
    saveCspCheckSettings();
  },
  { deep: true },
);

const calculateStatsFromAnalyses = (analyses: CspAnalysisResult[]) => {
  const allVulnerabilities = analyses.flatMap(
    (analysis) => analysis.vulnerabilities,
  );

  const severityStats = {
    high: allVulnerabilities.filter((v) => v.severity === "high").length,
    medium: allVulnerabilities.filter((v) => v.severity === "medium").length,
    low: allVulnerabilities.filter((v) => v.severity === "low").length,
    info: allVulnerabilities.filter((v) => v.severity === "info").length,
  };

  const typeStats: Record<string, number> = {};
  for (const vuln of allVulnerabilities) {
    typeStats[vuln.type] =
      (typeof typeStats[vuln.type] === "number" ? typeStats[vuln.type] : 0) + 1;
  }

  return {
    totalVulnerabilities: allVulnerabilities.length,
    severityStats,
    typeStats,
  };
};

const loadDashboardData = async () => {
  loading.value = true;
  try {
    // eslint-disable-next-line compat/compat
    const [statsData, analysesData] = await Promise.all([
      sdk.backend.getCspStats(),
      sdk.backend.getAllCspAnalyses(),
    ]);

    allAnalyses.value = analysesData;

    const allStats = calculateStatsFromAnalyses(allAnalyses.value);
    stats.value = {
      ...statsData,
      totalAnalyses: allAnalyses.value.length,
      totalVulnerabilities: allStats.totalVulnerabilities,
      severityStats: allStats.severityStats,
      typeStats: allStats.typeStats,
      lastAnalyzed: allAnalyses.value.length > 0 ? new Date() : null,
    };
  } catch (error) {
    console.error("Failed to load dashboard data:", error);
  } finally {
    loading.value = false;
  }
};

const refreshData = async () => {
  await loadDashboardData();
};

const startAutoRefresh = () => {
  if (
    autoRefreshEnabled.value === true &&
    refreshInterval.value === undefined
  ) {
    refreshInterval.value = window.setInterval(async () => {
      if (autoRefreshEnabled.value && !loading.value) {
        const currentTotalAnalyses = stats.value.totalAnalyses;

        try {
          const [newStats] = await Promise.all([sdk.backend.getCspStats()]);

          if (
            typeof newStats.totalAnalyses === "number" &&
            newStats.totalAnalyses !== currentTotalAnalyses
          ) {
            await loadDashboardData();
          }
        } catch (error) {
          console.error("Auto-refresh failed:", error);
        }
      }
    }, REFRESH_INTERVAL_MS);
  }
};

const stopAutoRefresh = () => {
  if (refreshInterval.value !== undefined) {
    window.clearInterval(refreshInterval.value);
    refreshInterval.value = undefined;
  }
};

const toggleAutoRefresh = () => {
  autoRefreshEnabled.value = !autoRefreshEnabled.value;
  if (autoRefreshEnabled.value) {
    startAutoRefresh();
  } else {
    stopAutoRefresh();
  }
};

const loadScopeSettings = async () => {
  try {
    const scopeSetting = await sdk.backend.getScopeRespecting();
    respectScope.value = scopeSetting;
  } catch (error) {
    console.error("Failed to load scope settings:", error);
  }
};

const loadCreateFindingsSettings = async () => {
  try {
    const findingsSetting = await sdk.backend.getCreateFindings();
    createFindings.value = findingsSetting;
  } catch (error) {
    console.error("Failed to load create findings settings:", error);
  }
};

const updateScopeRespecting = async (newValue: boolean) => {
  try {
    await sdk.backend.setScopeRespecting(newValue);
  } catch (error) {
    console.error("Failed to update scope setting:", error);
    respectScope.value = !newValue;
  }
};

const updateCreateFindings = async (newValue: boolean) => {
  try {
    await sdk.backend.setCreateFindings(newValue);
  } catch (error) {
    console.error("Failed to update create findings setting:", error);
    createFindings.value = !newValue;
  }
};

const clearCache = async () => {
  try {
    await sdk.backend.clearCspCache();
    await loadDashboardData();
  } catch (error) {
    console.error("Failed to clear cache:", error);
  }
};

const exportFindings = async (format: "json" | "csv") => {
  try {
    const data = await sdk.backend.exportCspFindings(format);

    // Create and trigger download
    const blob = new Blob([data], {
      type: format === "json" ? "application/json" : "text/csv",
    });
    // eslint-disable-next-line compat/compat
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `csp-findings.${format}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    // eslint-disable-next-line compat/compat
    URL.revokeObjectURL(url);
  } catch (error) {
    console.error("Failed to export findings:", error);
  }
};

const getSeverityBadgeClass = (severity: string) => {
  const classes: Record<string, string> = {
    high: "bg-red-500",
    medium: "bg-orange-500",
    low: "bg-yellow-500",
    info: "bg-blue-500",
  };
  const severityClass = classes[severity];
  if (
    severityClass !== null &&
    severityClass !== undefined &&
    severityClass.trim() !== ""
  ) {
    return severityClass;
  }
  return "bg-gray-500";
};

const formatDate = (date: Date | string) => {
  return new Date(date).toLocaleString();
};

const extractHostAndPath = (analysis: CspAnalysisResult) => {
  const firstPolicy = analysis.policies[0];

  if (firstPolicy?.url !== null && firstPolicy.url.trim() !== "") {
    try {
      let urlToparse = firstPolicy.url;
      if (
        !urlToparse.startsWith("http://") &&
        !urlToparse.startsWith("https://")
      ) {
        urlToparse = "https://" + urlToparse;
      }

      const url = new URL(urlToparse);
      return {
        host: url.hostname,
        path: url.pathname || "/",
      };
    } catch (error) {
      const parts = firstPolicy.url.split("/");
      if (parts.length >= 1) {
        const firstPart = parts[0];
        let hostPart = "N/A";
        if (
          firstPart !== null &&
          firstPart !== undefined &&
          firstPart.trim() !== ""
        ) {
          hostPart = firstPart.replace(/^https?:\/\//, "");
        }
        const pathPart = "/" + parts.slice(1).join("/");
        return {
          host: hostPart,
          path: pathPart === "/" && parts.length === 1 ? "/" : pathPart,
        };
      }
    }
  }

  return {
    host: "N/A",
    path: "N/A",
  };
};

const getSeverityPercentage = computed(() => {
  const total = stats.value.totalVulnerabilities;
  if (total === 0) return { high: 0, medium: 0, low: 0, info: 0 };

  return {
    high: (stats.value.severityStats.high / total) * 100,
    medium: (stats.value.severityStats.medium / total) * 100,
    low: (stats.value.severityStats.low / total) * 100,
    info: (stats.value.severityStats.info / total) * 100,
  };
});

// Convert settings object to array for table display
const cspChecksArray = computed(() => {
  return Object.entries(cspCheckSettings.value).map(([key, check]) => ({
    id: key,
    ...check,
  }));
});

// Group checks by category
const checksByCategory = computed(() => {
  const grouped: Record<string, unknown[]> = {};
  cspChecksArray.value.forEach((check) => {
    if (!grouped[check.category]) {
      grouped[check.category] = [];
    }
    grouped[check.category]?.push(check);
  });
  return grouped;
});

const enabledChecksCount = computed(() => {
  return Object.values(cspCheckSettings.value).filter((check) => check.enabled)
    .length;
});

const totalChecksCount = computed(() => {
  return Object.keys(cspCheckSettings.value).length;
});

// Quick preset functions
const enableAllChecks = () => {
  Object.keys(cspCheckSettings.value).forEach((key) => {
    cspCheckSettings.value[key as keyof typeof cspCheckSettings.value].enabled =
      true;
  });
  saveCspCheckSettings();
};

const disableAllChecks = () => {
  Object.keys(cspCheckSettings.value).forEach((key) => {
    cspCheckSettings.value[key as keyof typeof cspCheckSettings.value].enabled =
      false;
  });
  saveCspCheckSettings();
};

const setAggressiveMode = () => {
  enableAllChecks();
};

const setLightMode = () => {
  // Enable only critical checks
  Object.entries(cspCheckSettings.value).forEach(([key, check]) => {
    cspCheckSettings.value[key as keyof typeof cspCheckSettings.value].enabled =
      check.severity === "high" || check.category === "Critical";
  });
  saveCspCheckSettings();
};

const setRecommendedMode = () => {
  // Enable high and medium severity checks
  Object.entries(cspCheckSettings.value).forEach(([key, check]) => {
    cspCheckSettings.value[key as keyof typeof cspCheckSettings.value].enabled =
      check.severity === "high" || check.severity === "medium";
  });
  saveCspCheckSettings();
};

const loadCspCheckSettings = async () => {
  try {
    const backendSettings = await sdk.backend.getCspCheckSettings();

    // Update our frontend settings with backend state
    Object.keys(cspCheckSettings.value).forEach((key) => {
      if (backendSettings[key] !== undefined) {
        cspCheckSettings.value[
          key as keyof typeof cspCheckSettings.value
        ].enabled = backendSettings[key];
      }
    });
  } catch (error) {
    console.error("Failed to load CSP check settings:", error);
  }
};

const saveCspCheckSettings = async () => {
  try {
    const settingsToSave: Record<string, boolean> = {};
    Object.entries(cspCheckSettings.value).forEach(([key, check]) => {
      settingsToSave[key] = check.enabled;
    });

    await sdk.backend.setCspCheckSettings(settingsToSave);
  } catch (error) {
    console.error("Failed to save CSP check settings:", error);
  }
};

// Modal functions
const showVulnerabilityDetails = (
  vulnerability: unknown,
  analysis: CspAnalysisResult,
) => {
  selectedVulnerability.value = vulnerability;
  selectedAnalysisForModal.value = analysis;
  showVulnerabilityModal.value = true;
};

const closeVulnerabilityModal = () => {
  showVulnerabilityModal.value = false;
  selectedVulnerability.value = null;
  selectedAnalysisForModal.value = null;
};

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case "high":
      return "danger";
    case "medium":
      return "warning";
    case "low":
      return "info";
    case "info":
      return "secondary";
    default:
      return "secondary";
  }
};

const totalPages = computed(() =>
  Math.ceil(allAnalyses.value.length / itemsPerPage.value),
);

const paginatedAnalyses = computed(() => {
  const start = (currentPage.value - 1) * itemsPerPage.value;
  const end = start + itemsPerPage.value;
  return allAnalyses.value.slice(start, end);
});

const viewAnalysisDetails = (analysisData: CspAnalysisResult) => {
  if (selectedAnalysis.value?.requestId === analysisData.requestId) {
    selectedAnalysis.value = null;
  } else {
    selectedAnalysis.value = analysisData;
  }
};

const copyToClipboard = async (text: string, type: string) => {
  try {
    await navigator.clipboard.writeText(text);
    console.log(`${type} copied to clipboard`);
  } catch (error) {
    console.error("Failed to copy to clipboard:", error);
  }
};

const copyVulnerabilities = async (vulnerabilities: unknown[]) => {
  const vulnText = vulnerabilities
    .map((v) => {
      if (
        typeof v === "object" &&
        v !== null &&
        "type" in v &&
        "severity" in v &&
        "description" in v
      ) {
        return `${v.type} (${String(v.severity).toUpperCase()}): ${v.description}`;
      }
      return String(v);
    })
    .join("\n\n");
  await copyToClipboard(vulnText, "Vulnerabilities");
};

const copyBypassPayload = async (payload: string, name: string) => {
  await copyToClipboard(payload, `${name} Payload`);
};

const getVulnerabilityBypasses = (
  vulnerabilityType: string,
): BypassPayload[] => {
  return getBypassesForVulnerability(vulnerabilityType, bypassEntries.value);
};

const loadBypassData = async () => {
  loadingBypasses.value = true;
  try {
    // Load the full bypass database from backend
    const bypasses = await sdk.backend.getBypassDatabase();
    bypassEntries.value = bypasses;
    console.log(`Loaded ${bypasses.length} bypass payloads from database`);
  } catch (error) {
    console.error("Failed to load bypass data:", error);
    // Fallback to empty array
    bypassEntries.value = [];
  } finally {
    loadingBypasses.value = false;
  }
};

const copyBypassCode = async (code: string, domain: string) => {
  await copyToClipboard(code, `${domain} Bypass`);
};

// Filtered bypass entries based on search query
const filteredBypassEntries = computed(() => {
  if (!bypassSearchQuery.value.trim()) {
    return bypassEntries.value;
  }

  const query = bypassSearchQuery.value.toLowerCase();
  return bypassEntries.value.filter(
    (entry) =>
      entry.domain.toLowerCase().includes(query) ||
      entry.technique.toLowerCase().includes(query) ||
      entry.code.toLowerCase().includes(query),
  );
});

const getTechniqueColor = (technique: string): string => {
  switch (technique) {
    case "JSONP":
      return "success";
    case "AngularJS":
      return "danger";
    case "Alpine.js":
      return "info";
    case "HTMX":
      return "warning";
    case "Hyperscript":
      return "secondary";
    case "Script Injection":
      return "danger";
    case "Event Handler":
      return "warning";
    case "Link Preload":
      return "info";
    case "Iframe Injection":
      return "danger";
    default:
      return "secondary";
  }
};

const goToPage = (page: number) => {
  if (page >= 1 && page <= totalPages.value) {
    currentPage.value = page;
  }
};

const previousPage = () => {
  if (currentPage.value > 1) {
    currentPage.value--;
  }
};

const nextPage = () => {
  if (currentPage.value < totalPages.value) {
    currentPage.value++;
  }
};

// Helper function to safely update check settings
const updateCheckSetting = (checkId: string, enabled: boolean) => {
  (
    cspCheckSettings.value as Record<
      string,
      {
        enabled: boolean;
        name: string;
        category: string;
        severity: string;
        description: string;
      }
    >
  )[checkId].enabled = enabled;
};

const getCheckEnabled = (checkId: string): boolean => {
  return (
    (
      cspCheckSettings.value as Record<
        string,
        {
          enabled: boolean;
          name: string;
          category: string;
          severity: string;
          description: string;
        }
      >
    )[checkId]?.enabled ?? false
  );
};
</script>

<template>
  <div class="h-full p-4 overflow-y-auto">
    <!-- Header -->
    <div class="flex justify-between items-center mb-6">
      <div>
        <h1 class="text-3xl font-bold text-gray-900 dark:text-white">
          CSP Auditor
        </h1>
        <p class="text-gray-600 dark:text-gray-300">
          Content Security Policy vulnerability scanner
        </p>
        <div class="flex items-center gap-3 mt-1">
          <p class="text-xs text-gray-500 dark:text-gray-400">
            Made with ❤️ for the awesome Caido community by
            @GangGreenTemperTatum
          </p>
          <div v-if="autoRefreshEnabled" class="flex items-center gap-1">
            <div class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
            <span class="text-xs text-green-600 dark:text-green-400"
              >Auto-updating</span
            >
          </div>
        </div>
      </div>

      <div class="flex gap-4 items-center">
        <div class="flex items-center gap-2">
          <InputSwitch
            v-model="respectScope"
            @update:model-value="updateScopeRespecting"
          />
          <span class="text-xs text-gray-600 dark:text-gray-400">Scope</span>
        </div>
        <div class="flex items-center gap-2">
          <InputSwitch
            v-model="createFindings"
            @update:model-value="updateCreateFindings"
          />
          <span class="text-xs text-gray-600 dark:text-gray-400"
            >Create Findings</span
          >
        </div>
        <Button
          label="Refresh"
          icon="pi pi-refresh"
          :loading="loading"
          size="small"
          @click="refreshData"
        />
        <Button
          :label="autoRefreshEnabled ? 'Auto-Refresh: ON' : 'Auto-Refresh: OFF'"
          :icon="autoRefreshEnabled ? 'pi pi-pause' : 'pi pi-play'"
          :severity="autoRefreshEnabled ? 'success' : 'secondary'"
          size="small"
          :title="
            autoRefreshEnabled
              ? 'Auto-refresh every 5 seconds - Click to disable'
              : 'Auto-refresh disabled - Click to enable'
          "
          @click="toggleAutoRefresh"
        />
        <Button
          label="Export JSON"
          icon="pi pi-download"
          severity="secondary"
          size="small"
          @click="() => exportFindings('json')"
        />
        <Button
          label="Export CSV"
          icon="pi pi-download"
          severity="secondary"
          size="small"
          @click="() => exportFindings('csv')"
        />
        <Button
          label="Clear Cache"
          icon="pi pi-trash"
          severity="danger"
          size="small"
          @click="clearCache"
        />
      </div>
    </div>

    <!-- Loading State -->
    <div v-if="loading" class="flex justify-center items-center h-64">
      <ProgressBar mode="indeterminate" class="w-64" />
    </div>

    <!-- Main Content -->
    <div v-else class="space-y-6">
      <TabView v-model:active-index="activeTab" class="w-full">
        <!-- Dashboard Tab -->
        <TabPanel header="Dashboard">
          <div class="space-y-6">
            <!-- Stats Cards -->
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <Card>
                <template #content>
                  <div class="text-center">
                    <div class="text-2xl font-bold text-blue-600">
                      {{ stats.totalAnalyses }}
                    </div>
                    <div class="text-sm text-gray-600 dark:text-gray-300">
                      Total Analyses
                    </div>
                  </div>
                </template>
              </Card>

              <Card>
                <template #content>
                  <div class="text-center">
                    <div class="text-2xl font-bold text-red-600">
                      {{ stats.totalVulnerabilities }}
                    </div>
                    <div class="text-sm text-gray-600 dark:text-gray-300">
                      Total Vulnerabilities
                    </div>
                  </div>
                </template>
              </Card>

              <Card>
                <template #content>
                  <div class="text-center">
                    <div class="text-2xl font-bold text-red-500">
                      {{ stats.severityStats.high }}
                    </div>
                    <div class="text-sm text-gray-600 dark:text-gray-300">
                      High Severity
                    </div>
                  </div>
                </template>
              </Card>

              <Card>
                <template #content>
                  <div class="text-center">
                    <div class="text-2xl font-bold text-orange-500">
                      {{ stats.severityStats.medium }}
                    </div>
                    <div class="text-sm text-gray-600 dark:text-gray-300">
                      Medium Severity
                    </div>
                  </div>
                </template>
              </Card>
            </div>

            <!-- Severity Breakdown and Future Feature Panel -->
            <div class="grid grid-cols-2 gap-6">
              <!-- Left: Severity Breakdown -->
              <Card>
                <template #title>Vulnerability Severity Breakdown</template>
                <template #content>
                  <div v-if="stats.totalVulnerabilities > 0" class="space-y-4">
                    <div class="flex justify-between items-center">
                      <span class="font-medium"
                        >High ({{
                          getSeverityPercentage.high.toFixed(1)
                        }}%)</span
                      >
                      <Badge
                        :value="stats.severityStats.high"
                        :class="getSeverityBadgeClass('high')"
                      />
                    </div>
                    <ProgressBar
                      :value="getSeverityPercentage.high"
                      class="h-2"
                      :style="{ backgroundColor: '#ef4444' }"
                      :show-value="false"
                    />

                    <div class="flex justify-between items-center">
                      <span class="font-medium"
                        >Medium ({{
                          getSeverityPercentage.medium.toFixed(1)
                        }}%)</span
                      >
                      <Badge
                        :value="stats.severityStats.medium"
                        :class="getSeverityBadgeClass('medium')"
                      />
                    </div>
                    <ProgressBar
                      :value="getSeverityPercentage.medium"
                      class="h-2"
                      :style="{ backgroundColor: '#f97316' }"
                      :show-value="false"
                    />

                    <div class="flex justify-between items-center">
                      <span class="font-medium"
                        >Low ({{ getSeverityPercentage.low.toFixed(1) }}%)</span
                      >
                      <Badge
                        :value="stats.severityStats.low"
                        :class="getSeverityBadgeClass('low')"
                      />
                    </div>
                    <ProgressBar
                      :value="getSeverityPercentage.low"
                      class="h-2"
                      :style="{ backgroundColor: '#eab308' }"
                      :show-value="false"
                    />

                    <div class="flex justify-between items-center">
                      <span class="font-medium"
                        >Info ({{
                          getSeverityPercentage.info.toFixed(1)
                        }}%)</span
                      >
                      <Badge
                        :value="stats.severityStats.info"
                        :class="getSeverityBadgeClass('info')"
                      />
                    </div>
                    <ProgressBar
                      :value="getSeverityPercentage.info"
                      class="h-2"
                      :style="{ backgroundColor: '#3b82f6' }"
                      :show-value="false"
                    />
                  </div>
                  <div v-else class="text-center text-gray-500 py-8">
                    No vulnerabilities found yet. Start analyzing requests with
                    CSP headers.
                  </div>
                </template>
              </Card>

              <!-- Right: CSP Bypass Database -->
              <Card>
                <template #title>
                  <div class="flex items-center justify-between">
                    <span>🎯 CSP Bypass Database</span>
                    <div class="flex items-center gap-2">
                      <Badge
                        :value="bypassEntries.length"
                        severity="info"
                        class="text-xs"
                      />
                      <a
                        href="https://github.com/GangGreenTemperTatum/csp-auditor"
                        target="_blank"
                        class="text-xs text-blue-500 hover:text-blue-700 dark:text-blue-400"
                        title="View CSP Auditor project"
                      >
                        GitHub
                      </a>
                    </div>
                  </div>
                </template>
                <template #content>
                  <div v-if="loadingBypasses" class="text-center py-8">
                    <ProgressBar mode="indeterminate" class="w-full" />
                    <p class="text-sm text-gray-500 mt-2">
                      Loading bypass payloads...
                    </p>
                  </div>

                  <div v-else-if="bypassEntries.length > 0" class="space-y-3">
                    <div class="text-xs text-gray-600 dark:text-gray-400 mb-3">
                      Real-world CSP bypass techniques from security research
                      ({{ bypassEntries.length }} bypasses). Click to copy
                      payloads.
                    </div>

                    <!-- Search Box -->
                    <div class="relative mb-4">
                      <InputText
                        v-model="bypassSearchQuery"
                        placeholder="Search by domain, technique, or code..."
                        class="w-full pl-10"
                        size="small"
                      />
                      <i
                        class="pi pi-search absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400"
                      ></i>
                      <div
                        v-if="bypassSearchQuery"
                        class="text-xs text-gray-500 dark:text-gray-400 mt-1"
                      >
                        Showing {{ filteredBypassEntries.length }} of
                        {{ bypassEntries.length }} bypasses
                      </div>
                    </div>

                    <div class="max-h-80 overflow-y-auto space-y-2">
                      <div
                        v-for="entry in filteredBypassEntries"
                        :key="entry.id"
                        class="border border-gray-200 dark:border-gray-700 rounded-lg p-3 hover:bg-gray-50 dark:hover:bg-gray-900 cursor-pointer transition-colors"
                        :title="`Click to copy ${entry.domain} bypass payload`"
                        @click="copyBypassCode(entry.code, entry.domain)"
                      >
                        <div class="flex items-center justify-between mb-2">
                          <div class="flex items-center gap-2">
                            <span
                              class="text-sm font-mono text-blue-600 dark:text-blue-400"
                            >
                              {{ entry.domain }}
                            </span>
                            <Tag
                              :value="entry.technique"
                              :severity="getTechniqueColor(entry.technique)"
                              class="text-xs"
                            />
                          </div>
                          <Button
                            icon="pi pi-copy"
                            size="small"
                            severity="secondary"
                            text
                            title="Copy payload"
                            @click.stop="
                              copyBypassCode(entry.code, entry.domain)
                            "
                          />
                        </div>

                        <div
                          class="bg-gray-900 text-green-400 p-2 rounded text-xs font-mono overflow-x-auto"
                        >
                          <code>{{ entry.code }}</code>
                        </div>
                      </div>
                    </div>

                    <div
                      v-if="filteredBypassEntries.length === 0"
                      class="text-center text-gray-500 py-8"
                    >
                      <i class="pi pi-search text-2xl mb-2 block"></i>
                      <div class="text-sm">
                        No bypasses found matching "{{ bypassSearchQuery }}"
                      </div>
                      <div class="text-xs mt-1">
                        Try searching by domain, technique, or payload content
                      </div>
                    </div>

                    <div
                      v-if="filteredBypassEntries.length > 0"
                      class="text-xs text-gray-500 dark:text-gray-400 text-center mt-4 pt-3 border-t border-gray-200 dark:border-gray-700"
                    >
                      Want to contribute? Add bypasses to
                      <code>data/csp-bypass-data.tsv</code>
                    </div>
                  </div>

                  <div v-else class="text-center text-gray-500 py-8">
                    <i
                      class="pi pi-exclamation-triangle text-4xl mb-4 block"
                    ></i>
                    <div class="text-sm">
                      No bypass payloads loaded. Check data/csp-bypass-data.tsv
                    </div>
                  </div>
                </template>
              </Card>
            </div>

            <!-- Recent Analyses -->
            <Card>
              <template #title>
                <span>CSP Analyses ({{ allAnalyses.length }} total)</span>
              </template>
              <template #content>
                <!-- Table List View -->
                <div v-if="allAnalyses.length > 0">
                  <!-- Pagination Controls -->
                  <div class="flex justify-between items-center mb-4">
                    <div class="text-sm text-gray-600 dark:text-gray-400">
                      Page {{ currentPage }} of {{ totalPages }} (showing
                      {{ paginatedAnalyses.length }} of
                      {{ allAnalyses.length }} analyses)
                    </div>
                    <div class="flex items-center gap-2">
                      <Button
                        icon="pi pi-angle-left"
                        size="small"
                        severity="secondary"
                        outlined
                        :disabled="currentPage === 1"
                        title="Previous page"
                        @click="previousPage"
                      />
                      <template
                        v-for="page in Math.min(totalPages, 5)"
                        :key="page"
                      >
                        <Button
                          :label="String(page)"
                          size="small"
                          :severity="
                            currentPage === page ? 'primary' : 'secondary'
                          "
                          :outlined="currentPage !== page"
                          class="min-w-8"
                          @click="goToPage(page)"
                        />
                      </template>
                      <span v-if="totalPages > 5" class="text-gray-400"
                        >...</span
                      >
                      <Button
                        icon="pi pi-angle-right"
                        size="small"
                        severity="secondary"
                        outlined
                        :disabled="currentPage === totalPages"
                        title="Next page"
                        @click="nextPage"
                      />
                    </div>
                  </div>

                  <div class="overflow-x-auto">
                    <table class="w-full border-collapse table-fixed">
                      <thead>
                        <tr
                          class="border-b border-gray-200 dark:border-gray-700"
                        >
                          <th
                            class="text-left p-2 font-medium text-gray-700 dark:text-gray-300"
                            style="width: 100px"
                          >
                            Request ID
                          </th>
                          <th
                            class="text-left p-2 font-medium text-gray-700 dark:text-gray-300"
                            style="width: 130px"
                          >
                            Timestamp
                          </th>
                          <th
                            class="text-left p-2 font-medium text-gray-700 dark:text-gray-300"
                            style="max-width: 300px; min-width: 200px"
                          >
                            Host / Path
                          </th>
                          <th
                            class="text-left p-2 font-medium text-gray-700 dark:text-gray-300"
                            style="width: 120px"
                          >
                            Vulnerabilities
                          </th>
                          <th
                            class="text-left p-2 font-medium text-gray-700 dark:text-gray-300"
                            style="width: 70px"
                          >
                            Policies
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        <template
                          v-for="analysis in paginatedAnalyses"
                          :key="analysis.requestId"
                        >
                          <!-- Regular Table Row -->
                          <tr
                            class="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-900 cursor-pointer"
                            :class="{
                              'bg-blue-50 dark:bg-blue-950':
                                selectedAnalysis?.requestId ===
                                analysis.requestId,
                            }"
                            @click="viewAnalysisDetails(analysis)"
                          >
                            <td class="p-2" style="width: 100px">
                              <code
                                class="text-xs font-mono bg-gray-100 dark:bg-gray-700 px-1 py-0.5 rounded"
                              >
                                {{ analysis.requestId.slice(0, 6) }}
                              </code>
                            </td>
                            <td class="p-2" style="width: 130px">
                              <span class="text-xs">{{
                                formatDate(analysis.analyzedAt)
                              }}</span>
                            </td>
                            <td
                              class="p-2"
                              style="max-width: 300px; min-width: 200px"
                            >
                              <div class="flex flex-col gap-0.5">
                                <span
                                  class="text-sm font-medium text-gray-900 dark:text-white truncate"
                                  :title="extractHostAndPath(analysis).host"
                                >
                                  {{ extractHostAndPath(analysis).host }}
                                </span>
                                <span
                                  class="text-xs text-gray-600 dark:text-gray-400 truncate"
                                  :title="extractHostAndPath(analysis).path"
                                >
                                  {{ extractHostAndPath(analysis).path }}
                                </span>
                              </div>
                            </td>
                            <td class="p-2" style="width: 120px">
                              <div class="flex gap-1 flex-wrap">
                                <template
                                  v-for="vulnerability in analysis.vulnerabilities.slice(
                                    0,
                                    3,
                                  )"
                                  :key="vulnerability.id"
                                >
                                  <Badge
                                    :value="
                                      vulnerability.type.split('-')[1] ||
                                      vulnerability.type
                                    "
                                    :severity="
                                      getSeverityColor(vulnerability.severity)
                                    "
                                    class="text-xs cursor-pointer hover:bg-opacity-80 hover:scale-105 transition-all duration-200 border-2 border-transparent hover:border-current"
                                    :title="`Click to see details: ${vulnerability.type}\n${vulnerability.description}`"
                                    @click.stop="
                                      showVulnerabilityDetails(
                                        vulnerability,
                                        analysis,
                                      )
                                    "
                                  />
                                </template>
                                <Badge
                                  v-if="analysis.vulnerabilities.length > 3"
                                  :value="`+${analysis.vulnerabilities.length - 3}`"
                                  severity="secondary"
                                  class="text-xs cursor-pointer hover:bg-opacity-80 transition-colors"
                                  title="Click to see all vulnerabilities"
                                  @click.stop="viewAnalysisDetails(analysis)"
                                />
                              </div>
                            </td>
                            <td class="p-2" style="width: 70px">
                              <span class="text-sm font-medium">{{
                                analysis.policies.length
                              }}</span>
                            </td>
                          </tr>

                          <!-- Expanded Details Row -->
                          <tr
                            v-if="
                              selectedAnalysis?.requestId === analysis.requestId
                            "
                            class="bg-gray-50 dark:bg-gray-900"
                          >
                            <td colspan="5" class="p-0">
                              <div class="p-6 space-y-6">
                                <!-- Header Info -->
                                <div
                                  class="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 bg-white dark:bg-gray-800 rounded-lg border"
                                >
                                  <div>
                                    <label
                                      class="text-sm font-medium text-gray-500 dark:text-gray-400"
                                      >Request ID</label
                                    >
                                    <div class="mt-1">
                                      <code
                                        class="text-sm font-mono bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded border"
                                      >
                                        {{ selectedAnalysis.requestId }}
                                      </code>
                                    </div>
                                  </div>
                                  <div>
                                    <label
                                      class="text-sm font-medium text-gray-500 dark:text-gray-400"
                                      >Analyzed At</label
                                    >
                                    <div class="mt-1 text-sm">
                                      {{
                                        formatDate(selectedAnalysis.analyzedAt)
                                      }}
                                    </div>
                                  </div>
                                  <div>
                                    <label
                                      class="text-sm font-medium text-gray-500 dark:text-gray-400"
                                      >Total Issues</label
                                    >
                                    <div
                                      class="mt-1 text-lg font-bold text-red-600"
                                    >
                                      {{
                                        selectedAnalysis.vulnerabilities.length
                                      }}
                                    </div>
                                  </div>
                                </div>

                                <!-- Vulnerabilities Details -->
                                <div
                                  v-if="
                                    selectedAnalysis.vulnerabilities.length > 0
                                  "
                                >
                                  <div
                                    class="flex items-center justify-between mb-3"
                                  >
                                    <h3 class="text-lg font-semibold">
                                      Vulnerabilities Found
                                    </h3>
                                    <button
                                      class="text-sm text-blue-500 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                                      title="Copy all vulnerabilities to clipboard"
                                      @click="
                                        copyVulnerabilities(
                                          selectedAnalysis.vulnerabilities,
                                        )
                                      "
                                    >
                                      📋 Copy All
                                    </button>
                                  </div>
                                  <div
                                    class="grid grid-cols-1 lg:grid-cols-2 gap-4"
                                  >
                                    <div
                                      v-for="(
                                        vuln, index
                                      ) in selectedAnalysis.vulnerabilities"
                                      :key="index"
                                      class="border border-gray-200 dark:border-gray-700 rounded-lg p-4"
                                      :class="{
                                        'border-red-300 bg-red-50 dark:bg-red-950':
                                          vuln.severity === 'high',
                                        'border-orange-300 bg-orange-50 dark:bg-orange-950':
                                          vuln.severity === 'medium',
                                        'border-yellow-300 bg-yellow-50 dark:bg-yellow-950':
                                          vuln.severity === 'low',
                                        'border-blue-300 bg-blue-50 dark:bg-blue-950':
                                          vuln.severity === 'info',
                                      }"
                                    >
                                      <div
                                        class="flex items-start justify-between mb-2"
                                      >
                                        <h4
                                          class="font-medium text-gray-900 dark:text-white text-sm"
                                        >
                                          {{ vuln.type }}
                                        </h4>
                                        <Badge
                                          :value="vuln.severity.toUpperCase()"
                                          :severity="
                                            vuln.severity === 'high'
                                              ? 'danger'
                                              : vuln.severity === 'medium'
                                                ? 'warning'
                                                : vuln.severity === 'low'
                                                  ? 'info'
                                                  : 'secondary'
                                          "
                                          class="text-xs flex-shrink-0"
                                        />
                                      </div>
                                      <p
                                        class="text-xs text-gray-700 dark:text-gray-300 mb-2 leading-relaxed"
                                      >
                                        {{ vuln.description }}
                                      </p>
                                      <div
                                        v-if="vuln.remediation"
                                        class="text-xs text-gray-600 dark:text-gray-400 bg-white dark:bg-gray-800 p-2 rounded border-l-2 border-blue-500"
                                      >
                                        <strong>Remediation:</strong>
                                        {{ vuln.remediation }}
                                      </div>
                                    </div>
                                  </div>
                                </div>

                                <!-- CSP Policies Details -->
                                <div
                                  v-if="selectedAnalysis.policies.length > 0"
                                >
                                  <h3 class="text-lg font-semibold mb-3">
                                    CSP Policies
                                  </h3>
                                  <div class="space-y-3">
                                    <div
                                      v-for="(
                                        policy, index
                                      ) in selectedAnalysis.policies"
                                      :key="index"
                                      class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 bg-white dark:bg-gray-800"
                                    >
                                      <div
                                        class="flex items-center justify-between mb-2"
                                      >
                                        <h4
                                          class="font-medium text-gray-900 dark:text-white"
                                        >
                                          {{ policy.headerName }}
                                        </h4>
                                        <div class="flex gap-2 items-center">
                                          <button
                                            class="text-xs text-blue-500 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                                            title="Copy CSP policy to clipboard"
                                            @click="
                                              copyToClipboard(
                                                policy.headerValue,
                                                'CSP Policy',
                                              )
                                            "
                                          >
                                            📋 Copy
                                          </button>
                                          <Badge
                                            v-if="policy.isReportOnly"
                                            value="Report Only"
                                            severity="info"
                                            class="text-xs"
                                          />
                                          <Badge
                                            v-if="policy.isDeprecated"
                                            value="Deprecated"
                                            severity="warning"
                                            class="text-xs"
                                          />
                                        </div>
                                      </div>
                                      <div
                                        class="bg-gray-50 dark:bg-gray-900 p-3 rounded border"
                                      >
                                        <code
                                          class="text-sm font-mono break-all whitespace-pre-wrap"
                                          >{{ policy.headerValue }}</code
                                        >
                                      </div>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            </td>
                          </tr>
                        </template>
                      </tbody>
                    </table>
                  </div>
                </div>
                <div v-else class="text-center text-gray-500 py-8">
                  No analyses performed yet. CSP headers will be automatically
                  analyzed when detected in HTTP responses.
                </div>
              </template>
            </Card>

            <!-- Instructions -->
            <Card v-if="stats.totalAnalyses === 0">
              <template #title>Getting Started</template>
              <template #content>
                <div class="space-y-4">
                  <p class="text-gray-700 dark:text-gray-300">
                    The CSP Auditor automatically analyzes Content Security
                    Policy headers in HTTP responses. To start finding
                    vulnerabilities:
                  </p>
                  <ol
                    class="list-decimal list-inside space-y-2 text-gray-700 dark:text-gray-300"
                  >
                    <li>Browse to web applications that use CSP headers</li>
                    <li>
                      The plugin will automatically detect and analyze CSP
                      policies
                    </li>
                    <li>View findings in the Caido Findings tab</li>
                    <li>
                      Return here to see analysis statistics and export results
                    </li>
                  </ol>
                  <Divider />
                  <p class="text-sm text-gray-600 dark:text-gray-400">
                    The plugin detects various CSP vulnerabilities including
                    unsafe-inline, wildcards, user content hosts, and deprecated
                    headers.
                  </p>
                </div>
              </template>
            </Card>
          </div>
        </TabPanel>

        <!-- Settings Tab -->
        <TabPanel header="Settings">
          <div class="space-y-6">
            <!-- Settings Summary -->
            <Card>
              <template #title>Scan Configuration</template>
              <template #content>
                <div class="flex flex-col lg:flex-row gap-6 items-start">
                  <div class="flex-1">
                    <p class="text-gray-700 dark:text-gray-300 mb-4">
                      Configure which CSP vulnerabilities to scan for. You can
                      enable/disable individual checks or use preset scanning
                      modes.
                    </p>
                    <div class="text-sm text-gray-600 dark:text-gray-400">
                      <strong
                        >{{ enabledChecksCount }}/{{ totalChecksCount }}</strong
                      >
                      checks enabled
                    </div>
                  </div>

                  <!-- Preset Buttons -->
                  <div class="flex flex-col sm:flex-row gap-3">
                    <Button
                      label="Aggressive"
                      severity="danger"
                      size="small"
                      title="Enable all vulnerability checks for maximum security coverage"
                      @click="setAggressiveMode"
                    />
                    <Button
                      label="Recommended"
                      severity="success"
                      size="small"
                      title="Enable high and medium severity checks (recommended for most users)"
                      @click="setRecommendedMode"
                    />
                    <Button
                      label="Light"
                      severity="secondary"
                      size="small"
                      title="Enable only critical/high severity checks for faster scanning"
                      @click="setLightMode"
                    />
                    <Button
                      label="Disable All"
                      severity="secondary"
                      outlined
                      size="small"
                      @click="disableAllChecks"
                    />
                  </div>
                </div>
              </template>
            </Card>

            <!-- CSP Checks Configuration -->
            <Card>
              <template #title>CSP Vulnerability Checks</template>
              <template #content>
                <div class="space-y-8">
                  <div
                    v-for="(checks, category) in checksByCategory"
                    :key="category"
                  >
                    <h3
                      class="text-lg font-semibold mb-4 text-gray-900 dark:text-white border-b border-gray-200 dark:border-gray-700 pb-2"
                    >
                      {{ category }}
                    </h3>

                    <div class="grid grid-cols-1 gap-4">
                      <div
                        v-for="check in checks"
                        :key="check.id"
                        class="flex items-start gap-4 p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-900 transition-colors"
                      >
                        <InputSwitch
                          :model-value="getCheckEnabled(check.id)"
                          class="mt-1"
                          @update:model-value="
                            (value) => updateCheckSetting(check.id, value)
                          "
                        />

                        <div class="flex-1 min-w-0">
                          <div class="flex items-center gap-3 mb-2">
                            <h4
                              class="font-medium text-gray-900 dark:text-white"
                            >
                              {{ check.name }}
                            </h4>
                            <Badge
                              :value="check.severity.toUpperCase()"
                              :severity="
                                check.severity === 'high'
                                  ? 'danger'
                                  : check.severity === 'medium'
                                    ? 'warning'
                                    : check.severity === 'low'
                                      ? 'info'
                                      : 'secondary'
                              "
                              class="text-xs"
                            />
                          </div>
                          <p class="text-sm text-gray-600 dark:text-gray-400">
                            {{ check.description }}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </template>
            </Card>
          </div>
        </TabPanel>
      </TabView>
    </div>

    <!-- Vulnerability Details Modal Overlay -->
    <div
      v-if="showVulnerabilityModal"
      class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50"
      style="z-index: 9999"
      @click="closeVulnerabilityModal"
    >
      <div
        class="bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-4xl w-full mx-4 max-h-[90vh] overflow-y-auto"
        @click.stop
      >
        <!-- Modal Header -->
        <div
          class="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700"
        >
          <h2 class="text-xl font-semibold text-gray-900 dark:text-white">
            🔍
            {{
              selectedVulnerability?.type
                .replace(/-/g, " ")
                .replace(/\b\w/g, (l) => l.toUpperCase()) ||
              "Vulnerability Details"
            }}
          </h2>
          <Button
            icon="pi pi-times"
            severity="secondary"
            text
            rounded
            @click="closeVulnerabilityModal"
          />
        </div>

        <!-- Modal Content -->
        <div
          v-if="selectedVulnerability && selectedAnalysisForModal"
          class="p-6 space-y-6"
        >
          <!-- Vulnerability Overview -->
          <div
            class="border border-gray-200 dark:border-gray-700 rounded-lg p-4"
          >
            <div class="flex items-start justify-between mb-4">
              <div class="flex-1">
                <h3
                  class="text-lg font-semibold text-gray-900 dark:text-white mb-2"
                >
                  {{
                    selectedVulnerability.type
                      .replace(/-/g, " ")
                      .replace(/\b\w/g, (l) => l.toUpperCase())
                  }}
                </h3>
                <div class="flex items-center gap-3 mb-3">
                  <Tag
                    :value="selectedVulnerability.severity.toUpperCase()"
                    :severity="getSeverityColor(selectedVulnerability.severity)"
                  />
                  <span class="text-sm text-gray-600 dark:text-gray-400">
                    Directive:
                    <code
                      class="bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded text-xs"
                      >{{ selectedVulnerability.directive }}</code
                    >
                  </span>
                  <span
                    v-if="selectedVulnerability.cweId"
                    class="text-sm text-gray-600 dark:text-gray-400"
                  >
                    CWE-{{ selectedVulnerability.cweId }}
                  </span>
                </div>
              </div>
            </div>

            <div class="space-y-4">
              <div>
                <h4 class="font-medium text-gray-900 dark:text-white mb-2">
                  Description
                </h4>
                <p
                  class="text-gray-700 dark:text-gray-300 text-sm leading-relaxed"
                >
                  {{ selectedVulnerability.description }}
                </p>
              </div>

              <div>
                <h4 class="font-medium text-gray-900 dark:text-white mb-2">
                  Problematic Value
                </h4>
                <code
                  class="block bg-red-50 dark:bg-red-900/20 text-red-800 dark:text-red-200 p-3 rounded-md text-sm font-mono border border-red-200 dark:border-red-800"
                >
                  {{ selectedVulnerability.value }}
                </code>
              </div>

              <div>
                <h4 class="font-medium text-gray-900 dark:text-white mb-2">
                  Remediation
                </h4>
                <p
                  class="text-gray-700 dark:text-gray-300 text-sm leading-relaxed"
                >
                  {{ selectedVulnerability.remediation }}
                </p>
              </div>
            </div>
          </div>

          <!-- Bypass Examples Section -->
          <div
            v-if="
              getVulnerabilityBypasses(selectedVulnerability.type).length > 0
            "
            class="border border-gray-200 dark:border-gray-700 rounded-lg p-4"
          >
            <h4 class="font-medium text-gray-900 dark:text-white mb-3">
              🎯 Bypass Examples ({{
                getVulnerabilityBypasses(selectedVulnerability.type).length
              }})
              <span
                class="text-xs text-gray-500 dark:text-gray-400 font-normal ml-2"
              >
                from CSPBypass database
              </span>
            </h4>
            <div class="space-y-3">
              <div
                v-for="bypass in getVulnerabilityBypasses(
                  selectedVulnerability.type,
                )"
                :key="bypass.id"
                class="bg-gray-50 dark:bg-gray-800 rounded-lg p-4 border-l-4"
                :class="{
                  'border-green-500': bypass.difficulty === 'easy',
                  'border-yellow-500': bypass.difficulty === 'medium',
                  'border-red-500': bypass.difficulty === 'hard',
                }"
              >
                <div class="flex items-start justify-between mb-2">
                  <div class="flex items-center gap-2 flex-wrap">
                    <h5
                      class="font-medium text-gray-900 dark:text-white text-sm"
                    >
                      {{ bypass.name }}
                    </h5>
                    <Tag
                      :value="bypass.difficulty"
                      :severity="getDifficultyColor(bypass.difficulty)"
                      class="text-xs"
                    />
                    <span
                      class="text-xs text-gray-500 dark:text-gray-400 bg-gray-200 dark:bg-gray-700 px-2 py-1 rounded"
                    >
                      {{ bypass.technique }}
                    </span>
                    <span
                      v-if="bypass.domain"
                      class="text-xs text-blue-600 dark:text-blue-400 bg-blue-100 dark:bg-blue-900 px-2 py-1 rounded font-mono"
                    >
                      {{ bypass.domain }}
                    </span>
                    <span
                      v-if="bypass.source === 'cspbypass'"
                      class="text-xs text-green-600 dark:text-green-400 bg-green-100 dark:bg-green-900 px-2 py-1 rounded"
                    >
                      CSPBypass
                    </span>
                  </div>
                  <Button
                    icon="pi pi-copy"
                    size="small"
                    severity="secondary"
                    text
                    :title="`Copy ${bypass.name} payload`"
                    @click="copyBypassPayload(bypass.payload, bypass.name)"
                  />
                </div>

                <p class="text-xs text-gray-600 dark:text-gray-400 mb-3">
                  {{ bypass.description }}
                </p>

                <div
                  class="bg-gray-900 text-green-400 p-3 rounded-md font-mono text-xs overflow-x-auto"
                >
                  <code>{{ bypass.payload }}</code>
                </div>

                <div v-if="bypass.requirements" class="mt-2">
                  <span
                    class="text-xs font-medium text-gray-600 dark:text-gray-400"
                    >Requirements:</span
                  >
                  <div class="flex flex-wrap gap-1 mt-1">
                    <span
                      v-for="req in bypass.requirements"
                      :key="req"
                      class="text-xs bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 px-2 py-1 rounded"
                    >
                      {{ req }}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- CSP Policy Context -->
          <div
            class="border border-gray-200 dark:border-gray-700 rounded-lg p-4"
          >
            <h4 class="font-medium text-gray-900 dark:text-white mb-3">
              CSP Policy Context
            </h4>
            <div class="space-y-3">
              <div>
                <span
                  class="text-sm font-medium text-gray-600 dark:text-gray-400"
                  >Request ID:</span
                >
                <code
                  class="ml-2 text-sm font-mono bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded"
                >
                  {{ selectedAnalysisForModal.requestId }}
                </code>
              </div>

              <div>
                <span
                  class="text-sm font-medium text-gray-600 dark:text-gray-400"
                  >Analysis Date:</span
                >
                <span class="ml-2 text-sm text-gray-700 dark:text-gray-300">
                  {{ formatDate(selectedAnalysisForModal.analyzedAt) }}
                </span>
              </div>

              <div v-if="selectedAnalysisForModal.policies.length > 0">
                <span
                  class="text-sm font-medium text-gray-600 dark:text-gray-400 block mb-2"
                  >Complete CSP Policy:</span
                >
                <div
                  class="bg-gray-50 dark:bg-gray-800 rounded-md p-3 overflow-x-auto"
                >
                  <div
                    v-for="policy in selectedAnalysisForModal.policies"
                    :key="policy.id"
                    class="space-y-1"
                  >
                    <div class="text-xs text-gray-500 dark:text-gray-400 mb-1">
                      Header: {{ policy.headerName
                      }}{{ policy.isReportOnly ? " (Report-Only)" : "" }}
                    </div>
                    <code
                      class="block text-sm font-mono text-gray-800 dark:text-gray-200 whitespace-pre-wrap break-all"
                    >
                      {{ policy.headerValue }}
                    </code>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Additional Vulnerabilities in this Analysis -->
          <div
            v-if="selectedAnalysisForModal.vulnerabilities.length > 1"
            class="border border-gray-200 dark:border-gray-700 rounded-lg p-4"
          >
            <h4 class="font-medium text-gray-900 dark:text-white mb-3">
              Other Vulnerabilities in this Analysis ({{
                selectedAnalysisForModal.vulnerabilities.length - 1
              }}
              more)
            </h4>
            <div class="space-y-2">
              <div
                v-for="vuln in selectedAnalysisForModal.vulnerabilities.filter(
                  (v) => v.id !== selectedVulnerability.id,
                )"
                :key="vuln.id"
                class="flex items-center gap-3 p-2 bg-gray-50 dark:bg-gray-800 rounded cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                @click="selectedVulnerability = vuln"
              >
                <Tag
                  :value="vuln.severity.toUpperCase()"
                  :severity="getSeverityColor(vuln.severity)"
                  class="text-xs"
                />
                <span class="text-sm font-medium text-gray-900 dark:text-white">
                  {{
                    vuln.type
                      .replace(/-/g, " ")
                      .replace(/\b\w/g, (l) => l.toUpperCase())
                  }}
                </span>
                <code
                  class="text-xs bg-gray-200 dark:bg-gray-700 px-2 py-1 rounded"
                  >{{ vuln.directive }}</code
                >
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
