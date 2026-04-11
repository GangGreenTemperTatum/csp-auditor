import { useSDK } from "@/plugins/sdk";

function triggerDownload(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  // eslint-disable-next-line compat/compat
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  // eslint-disable-next-line compat/compat
  URL.revokeObjectURL(url);
}

export function useExportDownload() {
  const sdk = useSDK();

  const downloadAsJson = async () => {
    const result = await sdk.backend.exportFindings("json");
    if (result.kind === "Ok") {
      triggerDownload(result.value, "csp-findings.json", "application/json");
      sdk.window.showToast("Exported as JSON", { variant: "success" });
    } else {
      sdk.window.showToast("Export failed", { variant: "error" });
    }
  };

  const downloadAsCsv = async () => {
    const result = await sdk.backend.exportFindings("csv");
    if (result.kind === "Ok") {
      triggerDownload(result.value, "csp-findings.csv", "text/csv");
      sdk.window.showToast("Exported as CSV", { variant: "success" });
    } else {
      sdk.window.showToast("Export failed", { variant: "error" });
    }
  };

  return { downloadAsJson, downloadAsCsv };
}
