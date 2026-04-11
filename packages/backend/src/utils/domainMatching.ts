import { randomBytes } from "crypto";

import { USER_CONTENT_HOST_PATTERNS } from "../data/userContentHosts";
import { VULNERABLE_JS_HOST_ENTRIES } from "../data/vulnerableJsHosts";

export function createUniqueId(): string {
  return randomBytes(16).toString("hex");
}

function isSubdomainMatch(subdomain: string, domain: string): boolean {
  if (subdomain === domain) return true;
  return subdomain.endsWith(`.${domain}`);
}

export function stripDomainPrefix(domain: string): string {
  return domain
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "");
}

export function isUserContentHost(domain: string): boolean {
  const clean = stripDomainPrefix(domain);

  return USER_CONTENT_HOST_PATTERNS.some((pattern) => {
    if (pattern.startsWith("*.")) {
      const suffix = pattern.substring(2);
      return clean === suffix || clean.endsWith(`.${suffix}`);
    }
    return clean === pattern;
  });
}

export function isVulnerableJsHost(
  domain: string,
  path?: string,
): { isVulnerable: boolean; risk?: string } {
  const clean = stripDomainPrefix(domain);

  for (const entry of VULNERABLE_JS_HOST_ENTRIES) {
    if (clean === entry.domain || isSubdomainMatch(clean, entry.domain)) {
      if (entry.paths.length === 0) {
        return { isVulnerable: true, risk: entry.risk };
      }

      if (path !== undefined && path.trim() !== "") {
        const pathMatch = entry.paths.some((p) => path.includes(p));
        if (pathMatch) {
          return { isVulnerable: true, risk: entry.risk };
        }
      }
    }
  }

  return { isVulnerable: false };
}
