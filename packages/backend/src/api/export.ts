import type { SDK } from "caido:plugin";
import type { Result } from "shared";
import { err, ok } from "shared";

import { exportAsCsv, exportAsJson, getAllAnalyses } from "../services";

export function apiExportFindings(
  _sdk: SDK,
  format: "json" | "csv",
): Result<string> {
  const analyses = getAllAnalyses();

  if (format === "json") return ok(exportAsJson(analyses));
  if (format === "csv") return ok(exportAsCsv(analyses));

  return err(`Unsupported export format: ${format}`);
}
