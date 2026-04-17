import type { AnalysisResult } from "shared";

export function formatDate(date: Date | string): string {
  const parsed = new Date(date);
  if (isNaN(parsed.getTime())) return String(date);
  return parsed.toLocaleString();
}

export function extractHostAndPath(analysis: AnalysisResult): {
  host: string;
  path: string;
} {
  const firstPolicy = analysis.policies[0];

  if (firstPolicy?.url !== undefined && firstPolicy.url.trim() !== "") {
    try {
      let raw = firstPolicy.url;
      if (!raw.startsWith("http://") && !raw.startsWith("https://")) {
        raw = `https://${raw}`;
      }

      const parsed = new URL(raw);
      return { host: parsed.hostname, path: parsed.pathname || "/" };
    } catch {
      const parts = firstPolicy.url.split("/");
      const hostPart = parts[0];
      return {
        host:
          hostPart !== undefined && hostPart.trim() !== "" ? hostPart : "N/A",
        path: "/",
      };
    }
  }

  return { host: "N/A", path: "N/A" };
}
