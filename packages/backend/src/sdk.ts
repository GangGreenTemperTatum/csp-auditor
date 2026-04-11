import type { BackendSDK } from "./types";

let sdk: BackendSDK | undefined;

export function setSDK(instance: BackendSDK): void {
  sdk = instance;
}

export function requireSDK(): BackendSDK {
  if (sdk === undefined) {
    throw new Error("SDK not initialized");
  }
  return sdk;
}
