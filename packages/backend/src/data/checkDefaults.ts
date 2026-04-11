import { DEFAULT_CHECK_DEFINITIONS } from "shared";

export function buildDefaultCheckState(): Record<string, boolean> {
  const state: Record<string, boolean> = {};
  for (const checkId of Object.keys(DEFAULT_CHECK_DEFINITIONS)) {
    state[checkId] = true;
  }
  return state;
}
