import type { SDK } from "caido:plugin";
import type { BypassRecord, Result } from "shared";
import { ok } from "shared";

import { BYPASS_RECORDS } from "../data";

export function apiGetBypassRecords(_sdk: SDK): Result<BypassRecord[]> {
  return ok(BYPASS_RECORDS);
}
