import type { SDK } from "caido:plugin";
import type { Result } from "shared";
import { ok } from "shared";

import {
  getCheckSettings,
  getFindingsEnabled,
  getScopeEnabled,
  setCheckSettings,
  setFindingsEnabled,
  setScopeEnabled,
  updateSingleCheck,
} from "../services";

export function apiGetScopeEnabled(_sdk: SDK): Result<boolean> {
  return ok(getScopeEnabled());
}

export function apiSetScopeEnabled(_sdk: SDK, enabled: boolean): Result<void> {
  setScopeEnabled(enabled);
  return ok(undefined);
}

export function apiGetFindingsEnabled(_sdk: SDK): Result<boolean> {
  return ok(getFindingsEnabled());
}

export function apiSetFindingsEnabled(
  _sdk: SDK,
  enabled: boolean,
): Result<void> {
  setFindingsEnabled(enabled);
  return ok(undefined);
}

export function apiGetCheckSettings(
  _sdk: SDK,
): Result<Record<string, boolean>> {
  return ok(getCheckSettings());
}

export function apiSetCheckSettings(
  _sdk: SDK,
  settings: Record<string, boolean>,
): Result<void> {
  setCheckSettings(settings);
  return ok(undefined);
}

export function apiUpdateSingleCheck(
  _sdk: SDK,
  checkId: string,
  enabled: boolean,
): Result<void> {
  updateSingleCheck(checkId, enabled);
  return ok(undefined);
}
