# CSP Auditor Backend API

> 13 RPC endpoints for Content Security Policy vulnerability analysis. Usable from the frontend plugin or programmatically via the Caido SDK client in CI/CD pipelines.

## Quick Start

```typescript
const analyses = await sdk.backend.getAllAnalyses();
const summary = await sdk.backend.getSummary();
const exported = await sdk.backend.exportFindings("json");
```

Every API method returns `Result<T>`:

```typescript
type Result<T> =
  | { kind: "Ok"; value: T }
  | { kind: "Error"; error: string };

const result = await sdk.backend.getAllAnalyses();
if (result.kind === "Error") {
  sdk.window.showToast(result.error, { variant: "error" });
  return;
}
const analyses = result.value;
```

---

## API Reference

### Analysis

```typescript
getAllAnalyses(): Result<AnalysisResult[]>
getAnalysis(requestId: string): Result<AnalysisResult | undefined>
getSummary(): Result<AnalysisSummary>
clearCache(): Result<void>
```

### Settings

```typescript
getScopeEnabled(): Result<boolean>
setScopeEnabled(enabled: boolean): Result<void>
getFindingsEnabled(): Result<boolean>
setFindingsEnabled(enabled: boolean): Result<void>
getCheckSettings(): Result<Record<string, boolean>>
setCheckSettings(settings: Record<string, boolean>): Result<void>
updateSingleCheck(checkId: string, enabled: boolean): Result<void>
```

### Export

```typescript
exportFindings(format: "json" | "csv"): Result<string>
```

### Bypass Database

```typescript
getBypassRecords(): Result<BypassRecord[]>
```

---

## Analysis

CSP headers are automatically analyzed when detected in HTTP responses. The plugin intercepts responses via `onInterceptResponse`, extracts CSP headers, parses policies, and runs 20+ security checks.

### Get all analyses

```typescript
const result = sdk.backend.getAllAnalyses();
if (result.kind === "Ok") {
  for (const analysis of result.value) {
    console.log(`${analysis.requestId}: ${analysis.findings.length} findings`);
  }
}
```

### Get analysis summary

```typescript
const result = sdk.backend.getSummary();
if (result.kind === "Ok") {
  const summary = result.value;
  console.log(`Total: ${summary.totalAnalyses} analyses, ${summary.totalFindings} findings`);
  console.log(`High: ${summary.severityCounts.high}, Medium: ${summary.severityCounts.medium}`);
}
```

### Export findings

```typescript
const jsonResult = await sdk.backend.exportFindings("json");
const csvResult = await sdk.backend.exportFindings("csv");
```

### Clear cache

```typescript
sdk.backend.clearCache();
```

---

## Settings

### Scope filtering

When enabled, only requests matching the Caido scope are analyzed.

```typescript
await sdk.backend.setScopeEnabled(true);
const result = await sdk.backend.getScopeEnabled();
console.log(`Scope filtering: ${result.value}`);
```

### Auto-finding creation

When enabled, Caido findings are automatically created for detected vulnerabilities.

```typescript
await sdk.backend.setFindingsEnabled(true);
```

### Check configuration

Enable or disable individual security checks.

```typescript
const settings = await sdk.backend.getCheckSettings();
console.log(settings.value);

await sdk.backend.updateSingleCheck("script-wildcard", false);

await sdk.backend.setCheckSettings({
  "script-wildcard": true,
  "script-unsafe-inline": true,
  "script-unsafe-eval": false,
});
```

---

## Bypass Database

Access the built-in CSP bypass payload database (205 entries from CSPBypass research).

```typescript
const result = await sdk.backend.getBypassRecords();
if (result.kind === "Ok") {
  for (const record of result.value) {
    console.log(`${record.domain} [${record.technique}]: ${record.code}`);
  }
}
```

---

## Events

Events emitted from backend to frontend. Subscribe with `sdk.backend.onEvent()`.

```typescript
sdk.backend.onEvent("analysisUpdated", () => {
  console.log("Analysis cache changed - refetch data");
});
```

The `analysisUpdated` event fires when:

- A new analysis is added to the cache
- The cache is cleared
- No payload data - the frontend should refetch all analyses

---

## Types

All types from `"shared"`:

```typescript
import type {
  AnalysisResult,
  AnalysisSummary,
  ParsedPolicy,
  PolicyDirective,
  PolicyFinding,
  PolicySource,
  CheckId,
  SeverityLevel,
  BypassRecord,
  Result,
} from "shared";
```

