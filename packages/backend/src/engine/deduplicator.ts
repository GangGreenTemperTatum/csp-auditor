import type { PolicyFinding, SeverityLevel } from "shared";

const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export function deduplicateAndSort(findings: PolicyFinding[]): PolicyFinding[] {
  const seen = new Set<string>();
  const unique: PolicyFinding[] = [];

  for (const finding of findings) {
    const key = `${finding.checkId}|${finding.directive}|${finding.value}`;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(finding);
    }
  }

  return unique.sort(
    (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity],
  );
}
