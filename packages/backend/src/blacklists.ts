import { isSubdomainOf } from "./utils";

// User content hosts - domains known to host user-uploaded content
export const USER_CONTENT_HOSTS = [
  // GitHub
  "*.github.io",
  "github.com",
  "raw.githubusercontent.com",

  // Amazon S3
  "*.s3.amazonaws.com",
  "*.cloudfront.com",

  // Heroku hosting
  "*.herokuapp.com",

  // Dropbox
  "dl.dropboxusercontent.com",

  // AppEngine
  "*.appspot.com",

  // Google user files
  "googleusercontent.com",

  // Blogger - Comprehensive subdomain list
  "*.blogspot.ae", "*.blogspot.al", "*.blogspot.am", "*.blogspot.ba", "*.blogspot.be",
  "*.blogspot.bg", "*.blogspot.bj", "*.blogspot.ca", "*.blogspot.cf", "*.blogspot.ch",
  "*.blogspot.cl", "*.blogspot.co.at", "*.blogspot.co.id", "*.blogspot.co.il", 
  "*.blogspot.co.ke", "*.blogspot.co.nz", "*.blogspot.co.uk", "*.blogspot.co.za",
  "*.blogspot.com", "*.blogspot.com.ar", "*.blogspot.com.au", "*.blogspot.com.br",
  "*.blogspot.com.by", "*.blogspot.com.co", "*.blogspot.com.cy", "*.blogspot.com.ee",
  "*.blogspot.com.eg", "*.blogspot.com.es", "*.blogspot.com.mt", "*.blogspot.com.ng",
  "*.blogspot.com.tr", "*.blogspot.com.uy", "*.blogspot.cv", "*.blogspot.cz",
  "*.blogspot.de", "*.blogspot.dk", "*.blogspot.fi", "*.blogspot.fr", "*.blogspot.gr",
  "*.blogspot.hk", "*.blogspot.hr", "*.blogspot.hu", "*.blogspot.ie", "*.blogspot.in",
  "*.blogspot.is", "*.blogspot.it", "*.blogspot.jp", "*.blogspot.kr", "*.blogspot.li",
  "*.blogspot.lt", "*.blogspot.lu", "*.blogspot.md", "*.blogspot.mk", "*.blogspot.mr",
  "*.blogspot.mx", "*.blogspot.my", "*.blogspot.nl", "*.blogspot.no", "*.blogspot.pe",
  "*.blogspot.pt", "*.blogspot.qa", "*.blogspot.re", "*.blogspot.ro", "*.blogspot.rs",
  "*.blogspot.ru", "*.blogspot.se", "*.blogspot.sg", "*.blogspot.si", "*.blogspot.sk",
  "*.blogspot.sn", "*.blogspot.td", "*.blogspot.tw", "*.blogspot.ug", "*.blogspot.vn"
];

// JavaScript hosts with known vulnerable libraries
export const VULNERABLE_JS_HOSTS = [
  // AngularJS vulnerabilities - known security issues
  {
    domain: "cdnjs.cloudflare.com",
    paths: ["/ajax/libs/angular.js/"],
    risk: "AngularJS sandbox bypasses",
  },
  {
    domain: "code.angularjs.org",
    paths: [],
    risk: "AngularJS vulnerabilities",
  },
  {
    domain: "ajax.googleapis.com",
    paths: ["/ajax/libs/angularjs/", "/ajax/libs/yui/", "/jsapi", "/ajax/services/feed/find"],
    risk: "AngularJS and JSONP vulnerabilities",
  },

  // Yahoo vulnerabilities
  {
    domain: "d.yimg.com",
    paths: [],
    risk: "Yahoo JSONP callback vulnerabilities",
  },

  // JS Delivr
  {
    domain: "cdn.jsdelivr.net",
    paths: [],
    risk: "Various vulnerable library versions",
  },
];

export class BlacklistManager {
  static isUserContentHost(domain: string): boolean {
    const cleanDomain = domain
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .replace(/\/.*$/, "");

    return USER_CONTENT_HOSTS.some((pattern) => {
      if (pattern.startsWith("*")) {
        const suffix = pattern.substring(2); // Remove *.
        return cleanDomain.endsWith(suffix) || cleanDomain === suffix;
      }
      return cleanDomain === pattern;
    });
  }

  static isVulnerableJsHost(
    domain: string,
    path?: string,
  ): { isVulnerable: boolean; risk?: string } {
    const cleanDomain = domain
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .replace(/\/.*$/, "");

    for (const vulnHost of VULNERABLE_JS_HOSTS) {
      if (
        cleanDomain === vulnHost.domain ||
        isSubdomainOf(cleanDomain, vulnHost.domain)
      ) {
        // If no paths specified, entire domain is vulnerable
        if (vulnHost.paths.length === 0) {
          return { isVulnerable: true, risk: vulnHost.risk };
        }

        // Check if path matches any vulnerable paths
        if (
          path &&
          vulnHost.paths.some((vulnPath) => path.includes(vulnPath))
        ) {
          return { isVulnerable: true, risk: vulnHost.risk };
        }
      }
    }

    return { isVulnerable: false };
  }

  static checkDomainVariants(
    domain: string,
  ): Array<{ type: "user-content" | "vulnerable-js"; risk: string }> {
    const results: Array<{
      type: "user-content" | "vulnerable-js";
      risk: string;
    }> = [];

    if (this.isUserContentHost(domain)) {
      results.push({
        type: "user-content",
        risk: "Domain allows user-uploaded content that could contain malicious scripts",
      });
    }

    const vulnCheck = this.isVulnerableJsHost(domain);
    if (vulnCheck.isVulnerable) {
      results.push({
        type: "vulnerable-js",
        risk:
          vulnCheck.risk ||
          "Domain hosts known vulnerable JavaScript libraries",
      });
    }

    return results;
  }

  static getUserContentHostsCount(): number {
    return USER_CONTENT_HOSTS.length;
  }

  static getVulnerableJsHostsCount(): number {
    return VULNERABLE_JS_HOSTS.length;
  }
}
