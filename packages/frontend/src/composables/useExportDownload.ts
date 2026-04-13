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

  const downloadExport = async (
    format: "json" | "csv",
    filename: string,
    mimeType: string,
  ) => {
    try {
      const result = await sdk.backend.exportFindings(format);
      if (result.kind === "Ok") {
        triggerDownload(result.value, filename, mimeType);
        sdk.window.showToast(`Exported as ${format.toUpperCase()}`, {
          variant: "success",
        });
      } else {
        sdk.window.showToast("Export failed", { variant: "error" });
      }
    } catch {
      sdk.window.showToast("Export failed", { variant: "error" });
    }
  };

  const downloadAsJson = () =>
    downloadExport("json", "csp-findings.json", "application/json");

  const downloadAsCsv = () =>
    downloadExport("csv", "csp-findings.csv", "text/csv");

  return { downloadAsJson, downloadAsCsv };
}
