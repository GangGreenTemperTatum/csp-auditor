import type { AnalysisResult } from "shared";

export function exportAsJson(analyses: AnalysisResult[]): string {
  const allFindings = analyses.flatMap((a) => {
    const { host, path } = extractHostAndPath(a);
    return a.findings.map((f) => ({
      ...f,
      host,
      path,
      analyzedAt: a.analyzedAt.toISOString(),
    }));
  });

  return JSON.stringify(
    {
      exportedAt: new Date().toISOString(),
      totalFindings: allFindings.length,
      findings: allFindings,
    },
    undefined,
    2,
  );
}

function escapeCsvCell(value: string): string {
  if (
    value.includes(",") ||
    value.includes('"') ||
    value.includes("\n") ||
    value.includes("\r")
  ) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

export function exportAsCsv(analyses: AnalysisResult[]): string {
  const headers = [
    "ID",
    "Check",
    "Severity",
    "Directive",
    "Value",
    "Description",
    "Host",
    "Path",
    "Analyzed At",
    "Request ID",
  ];

  const rows = analyses.flatMap((a) => {
    const { host, path } = extractHostAndPath(a);
    return a.findings.map((f) =>
      [
        f.id,
        f.checkId,
        f.severity,
        f.directive,
        f.value,
        f.description,
        host,
        path,
        a.analyzedAt.toISOString(),
        f.requestId,
      ].map(escapeCsvCell),
    );
  });

  return [headers, ...rows].map((row) => row.join(",")).join("\n");
}

function extractHostAndPath(analysis: AnalysisResult): {
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
