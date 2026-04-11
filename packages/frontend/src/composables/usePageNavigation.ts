import { computed, ref } from "vue";

import Configuration from "@/views/Configuration.vue";
import Dashboard from "@/views/Dashboard.vue";
import Database from "@/views/Database.vue";

type Page = "Dashboard" | "Database" | "Configuration";

export function usePageNavigation() {
  const page = ref<Page>("Dashboard");

  const navItems = [
    {
      label: "Dashboard",
      isActive: () => page.value === "Dashboard",
      command: () => {
        page.value = "Dashboard";
      },
    },
    {
      label: "Database",
      isActive: () => page.value === "Database",
      command: () => {
        page.value = "Database";
      },
    },
    {
      label: "Configuration",
      isActive: () => page.value === "Configuration",
      command: () => {
        page.value = "Configuration";
      },
    },
  ];

  const component = computed(() => {
    switch (page.value) {
      case "Dashboard":
        return Dashboard;
      case "Database":
        return Database;
      case "Configuration":
        return Configuration;
      default:
        return undefined;
    }
  });

  return { page, navItems, component };
}
