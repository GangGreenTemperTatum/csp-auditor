import { useSDK } from "@/plugins/sdk";

export function useClipboard() {
  const sdk = useSDK();

  const copyToClipboard = async (text: string, label?: string) => {
    try {
      await navigator.clipboard.writeText(text);
      sdk.window.showToast(label ?? "Copied to clipboard", {
        variant: "success",
      });
    } catch {
      sdk.window.showToast("Failed to copy to clipboard", {
        variant: "error",
      });
    }
  };

  return { copyToClipboard };
}
