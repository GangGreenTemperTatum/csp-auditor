// CSP bypass database generated from data/csp-bypass-data.tsv
// This file is auto-generated - do not edit manually

import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

let cachedData: string | undefined = undefined;
let cachedCount: number | undefined = undefined;

export const getCSPBypassData = (): string => {
  if (cachedData === undefined) {
    try {
      // Read the TSV file from the project root
      const tsvPath = join(process.cwd(), "data", "csp-bypass-data.tsv");
      cachedData = readFileSync(tsvPath, "utf-8");
    } catch (error) {
      // Fallback to relative paths
      try {
        const currentDir = dirname(fileURLToPath(import.meta.url));
        const tsvPath = join(
          currentDir,
          "..",
          "..",
          "..",
          "data",
          "csp-bypass-data.tsv",
        );
        cachedData = readFileSync(tsvPath, "utf-8");
      } catch (fallbackError) {
        // Final fallback to absolute path
        try {
          cachedData = readFileSync(
            "/Users/ads/git/csp-auditor/data/csp-bypass-data.tsv",
            "utf-8",
          );
        } catch (finalError) {
          console.error(
            "Failed to load TSV data from all paths: " + String(finalError),
          );
          cachedData = "Domain\tCode\n"; // Empty TSV with header
        }
      }
    }
  }
  return cachedData;
};

export const getBypassCount = (): number => {
  if (cachedCount === undefined) {
    const data = getCSPBypassData();
    const lines = data.trim().split("\n");
    cachedCount = Math.max(0, lines.length - 1); // Subtract 1 for header
  }
  return cachedCount;
};

// Legacy exports for backward compatibility
export const CSP_BYPASS_DATA = getCSPBypassData();
export const BYPASS_COUNT = getBypassCount();
