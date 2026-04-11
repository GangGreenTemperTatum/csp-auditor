import { defineStore } from "pinia";

import { useAnalysesState } from "./useAnalysesState";

export const useAnalysesStore = defineStore("stores.analyses", () => {
  return {
    ...useAnalysesState(),
  };
});
