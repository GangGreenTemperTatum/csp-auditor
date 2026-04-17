import type { AnalysisResult } from "shared";

import { exportAsCsv, exportAsJson } from "./exportService";

function fakeAnalysis(overrides?: Partial<AnalysisResult>): AnalysisResult {
  return {
    requestId: "req-1",
    policies: [
      {
        id: "p-1",
        requestId: "req-1",
        headerName: "content-security-policy",
        headerValue: "default-src 'self'",
        directives: new Map(),
        isReportOnly: false,
        isDeprecated: false,
        parsedAt: new Date("2025-01-01"),
        url: "https://example.com/page",
      },
    ],
    findings: [
      {
        id: "f-1",
        checkId: "script-wildcard",
        severity: "high",
        directive: "script-src",
        value: "*",
        description: "Wildcard detected",
        remediation: "Remove wildcard",
        requestId: "req-1",
      },
    ],
    analyzedAt: new Date("2025-01-01"),
    ...overrides,
  };
}

describe("exportAsJson", () => {
  it("formats findings as JSON with metadata", () => {
    const json = exportAsJson([fakeAnalysis()]);
    const parsed = JSON.parse(json);
    expect(parsed.totalFindings).toBe(1);
    expect(parsed.findings[0].checkId).toBe("script-wildcard");
    expect(parsed.findings[0].host).toBe("example.com");
    expect(parsed.exportedAt).toBeDefined();
  });

  it("handles empty analyses", () => {
    const json = exportAsJson([]);
    const parsed = JSON.parse(json);
    expect(parsed.totalFindings).toBe(0);
    expect(parsed.findings).toHaveLength(0);
  });
});

describe("exportAsCsv", () => {
  it("formats findings as CSV with headers", () => {
    const csv = exportAsCsv([fakeAnalysis()]);
    const lines = csv.split("\n");
    expect(lines[0]).toContain("ID,Check,Severity");
    expect(lines[1]).toContain("script-wildcard");
    expect(lines[1]).toContain("high");
  });

  it("handles empty analyses", () => {
    const csv = exportAsCsv([]);
    const lines = csv.split("\n");
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("ID,Check,Severity");
  });
});
