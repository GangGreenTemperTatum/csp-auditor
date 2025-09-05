import { randomBytes } from "crypto";

export function generateId(): string {
  return randomBytes(16).toString("hex");
}

export function normalizeUrl(url: string): string {
  try {
    const urlObj = new URL(url);
    return `${urlObj.protocol}//${urlObj.host}`;
  } catch {
    return url;
  }
}

export function extractDomain(url: string): string {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch {
    return url;
  }
}

export function matchesPattern(value: string, pattern: string): boolean {
  // Simple wildcard matching for CSP patterns
  if (pattern === "*") return true;

  if (pattern.startsWith("*")) {
    const suffix = pattern.substring(1);
    return value.endsWith(suffix);
  }

  if (pattern.endsWith("*")) {
    const prefix = pattern.substring(0, pattern.length - 1);
    return value.startsWith(prefix);
  }

  return value === pattern;
}

export function isSubdomainOf(subdomain: string, domain: string): boolean {
  if (subdomain === domain) return true;
  return subdomain.endsWith("." + domain);
}
