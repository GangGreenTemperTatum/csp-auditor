import type { CheckId, ParsedPolicy, PolicyFinding } from "shared";

import { AI_ML_HOSTS, WEB3_HOSTS } from "../../data";
import { emitFinding, isCheckEnabled } from "../../utils/findings";

const CDN_RISK_HOSTS = [
  "polyfill.io",
  "cdn.jsdelivr.net",
  "unpkg.com",
  "cdnjs.cloudflare.com",
  "cdn.skypack.dev",
];

type HostCheckConfig = {
  hosts: string[];
  checkId: CheckId;
};

const HOST_CHECKS: HostCheckConfig[] = [
  { hosts: AI_ML_HOSTS.map((h) => h.domain), checkId: "ai-ml-host" },
  { hosts: WEB3_HOSTS.map((h) => h.domain), checkId: "web3-host" },
  { hosts: CDN_RISK_HOSTS, checkId: "cdn-supply-chain" },
];

export function runModernThreatChecks(
  policy: ParsedPolicy,
  enabledChecks?: Record<string, boolean>,
): PolicyFinding[] {
  const findings: PolicyFinding[] = [];

  for (const config of HOST_CHECKS) {
    if (!isCheckEnabled(config.checkId, enabledChecks)) continue;

    for (const [, directive] of policy.directives) {
      for (const value of directive.values) {
        for (const host of config.hosts) {
          if (value === host || value.endsWith(`.${host}`)) {
            findings.push(
              emitFinding(
                config.checkId,
                directive.name,
                value,
                policy.requestId,
                `${host} integration detected`,
              ),
            );
          }
        }
      }
    }
  }

  return findings;
}
