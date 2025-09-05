// Removed unused import: isSubdomainOf

/**
 * Enhanced Modern Threat Intelligence for CSP Analysis
 * Beyond legacy limitations - 2024+ threat landscape
 */

// Modern supply chain attack vectors (2023-2024)
export const MODERN_SUPPLY_CHAIN_RISKS = [
  // CDN compromise incidents
  {
    domain: "polyfill.io",
    risk: "Compromised CDN serving malicious polyfills",
    severity: "high",
  },
  {
    domain: "bootcdn.cn",
    risk: "Chinese CDN with potential state-level risks",
    severity: "high",
  },
  {
    domain: "staticfile.org",
    risk: "Unverified Chinese CDN",
    severity: "medium",
  },

  // Package manager CDNs with supply chain risks
  {
    domain: "unpkg.com",
    risk: "NPM package CDN - supply chain attack vector",
    severity: "medium",
  },
  {
    domain: "cdn.skypack.dev",
    risk: "ES module CDN with potential risks",
    severity: "medium",
  },
  {
    domain: "jspm.dev",
    risk: "Module CDN with limited security guarantees",
    severity: "medium",
  },
];

// AI/ML service endpoints (potential data exfiltration)
export const AI_ML_SERVICE_RISKS = [
  {
    domain: "api.openai.com",
    risk: "AI API - potential data exfiltration",
    severity: "medium",
  },
  {
    domain: "api.anthropic.com",
    risk: "AI API - potential sensitive data exposure",
    severity: "medium",
  },
  {
    domain: "huggingface.co",
    risk: "ML model hosting - code execution risks",
    severity: "medium",
  },
  {
    domain: "replicate.com",
    risk: "ML API service - data privacy concerns",
    severity: "medium",
  },
  {
    domain: "colab.research.google.com",
    risk: "Jupyter notebook execution environment",
    severity: "high",
  },
];

// Cryptocurrency/Web3 integration risks
export const WEB3_INTEGRATION_RISKS = [
  {
    domain: "metamask.io",
    risk: "Wallet integration - financial transaction risks",
    severity: "high",
  },
  {
    domain: "walletconnect.org",
    risk: "Cross-wallet protocol - authentication bypass",
    severity: "high",
  },
  {
    domain: "uniswap.org",
    risk: "DeFi protocol - financial manipulation",
    severity: "high",
  },
  {
    domain: "pancakeswap.finance",
    risk: "DeFi exchange - smart contract risks",
    severity: "high",
  },
  {
    domain: "web3.storage",
    risk: "Decentralized storage - content integrity issues",
    severity: "medium",
  },
];

// Social media embed risks (privacy and tracking)
export const SOCIAL_EMBED_RISKS = [
  {
    domain: "platform.twitter.com",
    risk: "Twitter embed tracking and XSS risks",
    severity: "medium",
  },
  {
    domain: "connect.facebook.net",
    risk: "Facebook tracking and data collection",
    severity: "medium",
  },
  {
    domain: "www.instagram.com",
    risk: "Instagram embed privacy concerns",
    severity: "low",
  },
  {
    domain: "platform.linkedin.com",
    risk: "LinkedIn tracking integration",
    severity: "medium",
  },
  {
    domain: "assets.pinterest.com",
    risk: "Pinterest tracking and analytics",
    severity: "low",
  },
];

// Modern analytics and tracking (2024 landscape)
export const MODERN_TRACKING_RISKS = [
  {
    domain: "googletagmanager.com",
    risk: "Comprehensive user tracking and analytics",
    severity: "medium",
  },
  {
    domain: "hotjar.com",
    risk: "Session recording and user behavior tracking",
    severity: "high",
  },
  {
    domain: "fullstory.com",
    risk: "Complete session recording including sensitive data",
    severity: "high",
  },
  {
    domain: "logrocket.com",
    risk: "Application monitoring with PII exposure",
    severity: "high",
  },
  {
    domain: "sentry.io",
    risk: "Error tracking that may capture sensitive data",
    severity: "medium",
  },
];

// Gaming and metaverse platforms
export const GAMING_METAVERSE_RISKS = [
  {
    domain: "unity3d.com",
    risk: "Unity WebGL player - arbitrary code execution",
    severity: "high",
  },
  {
    domain: "unrealengine.com",
    risk: "Unreal Engine web player risks",
    severity: "high",
  },
  {
    domain: "roblox.com",
    risk: "User-generated content platform",
    severity: "medium",
  },
  {
    domain: "minecraft.net",
    risk: "Gaming platform with user content",
    severity: "medium",
  },
];

// Enhanced user content hosts (2024 update)
export const ENHANCED_USER_CONTENT_HOSTS = [
  // All previous hosts plus modern platforms
  ...[
    "*.github.io",
    "raw.githubusercontent.com",
    "*.s3.amazonaws.com",
    "*.herokuapp.com",
  ],

  // Modern development platforms
  "replit.com",
  "*.repl.co",
  "codesandbox.io",
  "*.csb.app",
  "stackblitz.com",
  "*.stackblitz.io",
  "glitch.com",
  "*.glitch.me",

  // Modern hosting platforms
  "vercel.app",
  "*.vercel.app",
  "netlify.app",
  "*.netlify.app",
  "render.com",
  "*.onrender.com",
  "railway.app",
  "*.railway.app",

  // No-code platforms
  "webflow.io",
  "*.webflow.io",
  "bubble.io",
  "*.bubble.io",
  "notion.so",
  "*.notion.so",
  "airtable.com",
  "*.airtable.com",
];

// Enhanced vulnerable JS detection with CVE mapping
export const ENHANCED_VULNERABLE_JS = [
  // jQuery vulnerabilities
  {
    domain: "code.jquery.com",
    versions: ["<3.5.0"],
    cve: ["CVE-2020-11022", "CVE-2020-11023"],
    risk: "DOM-based XSS vulnerabilities in jQuery versions < 3.5.0",
  },

  // AngularJS (end-of-life, inherently vulnerable)
  {
    domain: "ajax.googleapis.com",
    paths: ["/ajax/libs/angularjs/"],
    cve: ["CVE-2023-26116", "CVE-2022-25844"],
    risk: "AngularJS template injection and sandbox bypass (EOL framework)",
  },

  // Lodash vulnerabilities
  {
    domain: "cdnjs.cloudflare.com",
    paths: ["/ajax/libs/lodash/"],
    versions: ["<4.17.21"],
    cve: ["CVE-2021-23337"],
    risk: "Prototype pollution in Lodash versions < 4.17.21",
  },

  // Moment.js (deprecated, security concerns)
  {
    domain: "cdnjs.cloudflare.com",
    paths: ["/ajax/libs/moment.js/"],
    cve: [],
    risk: "Moment.js is deprecated and has known security/performance issues",
  },
];

export class EnhancedBlacklistManager {
  /**
   * Check for modern supply chain risks
   */
  static checkSupplyChainRisk(domain: string): {
    isRisky: boolean;
    risk?: string;
    severity?: string;
  } {
    const cleanDomain = this.cleanDomain(domain);

    for (const threat of MODERN_SUPPLY_CHAIN_RISKS) {
      if (cleanDomain.includes(threat.domain)) {
        return {
          isRisky: true,
          risk: threat.risk,
          severity: threat.severity,
        };
      }
    }

    return { isRisky: false };
  }

  /**
   * Advanced AI/ML service risk analysis
   */
  static checkAiMlServiceRisk(domain: string): {
    isRisky: boolean;
    risk?: string;
    severity?: string;
  } {
    const cleanDomain = this.cleanDomain(domain);

    for (const service of AI_ML_SERVICE_RISKS) {
      if (cleanDomain.includes(service.domain)) {
        return {
          isRisky: true,
          risk: service.risk,
          severity: service.severity,
        };
      }
    }

    return { isRisky: false };
  }

  /**
   * Web3/Cryptocurrency integration risks
   */
  static checkWeb3Risk(domain: string): {
    isRisky: boolean;
    risk?: string;
    severity?: string;
  } {
    const cleanDomain = this.cleanDomain(domain);

    for (const web3Risk of WEB3_INTEGRATION_RISKS) {
      if (cleanDomain.includes(web3Risk.domain)) {
        return {
          isRisky: true,
          risk: web3Risk.risk,
          severity: web3Risk.severity,
        };
      }
    }

    return { isRisky: false };
  }

  /**
   * Enhanced user content host detection
   */
  static isEnhancedUserContentHost(domain: string): boolean {
    const cleanDomain = this.cleanDomain(domain);

    return ENHANCED_USER_CONTENT_HOSTS.some((pattern) => {
      if (pattern.startsWith("*")) {
        const suffix = pattern.substring(2);
        return cleanDomain.endsWith(suffix) || cleanDomain === suffix;
      }
      return cleanDomain === pattern;
    });
  }

  /**
   * Advanced vulnerable JS detection with CVE mapping
   */
  static checkEnhancedVulnerableJs(
    domain: string,
    path?: string,
  ): {
    isVulnerable: boolean;
    risk?: string;
    cve?: string[];
    versions?: string[];
  } {
    const cleanDomain = this.cleanDomain(domain);

    for (const vulnJs of ENHANCED_VULNERABLE_JS) {
      if (cleanDomain.includes(vulnJs.domain)) {
        // Check path matching if specified
        if (vulnJs.paths && path) {
          const pathMatch = vulnJs.paths.some((vulnPath) =>
            path.includes(vulnPath),
          );
          if (pathMatch) {
            return {
              isVulnerable: true,
              risk: vulnJs.risk,
              cve: vulnJs.cve,
              versions: vulnJs.versions,
            };
          }
        } else if (!vulnJs.paths) {
          // Domain-level vulnerability
          return {
            isVulnerable: true,
            risk: vulnJs.risk,
            cve: vulnJs.cve,
            versions: vulnJs.versions,
          };
        }
      }
    }

    return { isVulnerable: false };
  }

  /**
   * Comprehensive modern threat analysis
   */
  static analyzeModernThreats(
    domain: string,
    path?: string,
  ): Array<{
    type: string;
    severity: string;
    risk: string;
    cve?: string[];
  }> {
    const threats: Array<{
      type: string;
      severity: string;
      risk: string;
      cve?: string[];
    }> = [];

    // Check all modern threat categories
    const supplyChain = this.checkSupplyChainRisk(domain);
    if (supplyChain.isRisky) {
      threats.push({
        type: "supply-chain",
        severity: supplyChain.severity || "medium",
        risk: supplyChain.risk || "Supply chain risk detected",
      });
    }

    const aiMl = this.checkAiMlServiceRisk(domain);
    if (aiMl.isRisky) {
      threats.push({
        type: "ai-ml-service",
        severity: aiMl.severity || "medium",
        risk: aiMl.risk || "AI/ML service integration risk",
      });
    }

    const web3 = this.checkWeb3Risk(domain);
    if (web3.isRisky) {
      threats.push({
        type: "web3-integration",
        severity: web3.severity || "high",
        risk: web3.risk || "Web3/Cryptocurrency integration risk",
      });
    }

    const vulnJs = this.checkEnhancedVulnerableJs(domain, path);
    if (vulnJs.isVulnerable) {
      threats.push({
        type: "vulnerable-js",
        severity: "high",
        risk: vulnJs.risk || "Vulnerable JavaScript library detected",
        cve: vulnJs.cve,
      });
    }

    return threats;
  }

  /**
   * Privacy and tracking risk assessment
   */
  static checkPrivacyTrackingRisk(domain: string): {
    isTracking: boolean;
    risk?: string;
    severity?: string;
  } {
    const cleanDomain = this.cleanDomain(domain);

    const allTrackingRisks = [...SOCIAL_EMBED_RISKS, ...MODERN_TRACKING_RISKS];

    for (const tracker of allTrackingRisks) {
      if (cleanDomain.includes(tracker.domain)) {
        return {
          isTracking: true,
          risk: tracker.risk,
          severity: tracker.severity,
        };
      }
    }

    return { isTracking: false };
  }

  private static cleanDomain(domain: string): string {
    return domain
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .replace(/\/.*$/, "")
      .replace(/^www\./, "");
  }

  /**
   * Get comprehensive threat intelligence summary
   */
  static getThreatIntelligenceSummary(): {
    supplyChainThreats: number;
    aiMlRisks: number;
    web3Risks: number;
    userContentHosts: number;
    vulnerableJsLibraries: number;
    trackingServices: number;
  } {
    return {
      supplyChainThreats: MODERN_SUPPLY_CHAIN_RISKS.length,
      aiMlRisks: AI_ML_SERVICE_RISKS.length,
      web3Risks: WEB3_INTEGRATION_RISKS.length,
      userContentHosts: ENHANCED_USER_CONTENT_HOSTS.length,
      vulnerableJsLibraries: ENHANCED_VULNERABLE_JS.length,
      trackingServices: [...SOCIAL_EMBED_RISKS, ...MODERN_TRACKING_RISKS]
        .length,
    };
  }
}
