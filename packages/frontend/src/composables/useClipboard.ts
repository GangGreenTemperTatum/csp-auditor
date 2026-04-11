import { useSDK } from "@/plugins/sdk";

export function useClipboard() {
  const sdk = useSDK();

  const copyToClipboard = async (text: string, label?: string) => {
    await navigator.clipboard.writeText(text);
    sdk.window.showToast(label ?? "Copied to clipboard", {
      variant: "success",
    });
  };

  return { copyToClipboard };
}
