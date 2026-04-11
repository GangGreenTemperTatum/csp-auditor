type VulnerableJsHost = {
  domain: string;
  paths: string[];
  risk: string;
  cves?: string[];
};

export const VULNERABLE_JS_HOST_ENTRIES: VulnerableJsHost[] = [
  {
    domain: "cdnjs.cloudflare.com",
    paths: [
      "/ajax/libs/angular.js/",
      "/ajax/libs/lodash/",
      "/ajax/libs/moment.js/",
    ],
    risk: "AngularJS sandbox bypasses, prototype pollution in Lodash",
    cves: ["CVE-2023-26116", "CVE-2021-23337"],
  },
  {
    domain: "code.angularjs.org",
    paths: [],
    risk: "AngularJS template injection (EOL framework)",
    cves: ["CVE-2023-26116", "CVE-2022-25844"],
  },
  {
    domain: "ajax.googleapis.com",
    paths: [
      "/ajax/libs/angularjs/",
      "/ajax/libs/yui/",
      "/jsapi",
      "/ajax/services/feed/find",
    ],
    risk: "AngularJS and JSONP callback vulnerabilities",
  },
  {
    domain: "d.yimg.com",
    paths: [],
    risk: "Yahoo JSONP callback vulnerabilities",
  },
  {
    domain: "cdn.jsdelivr.net",
    paths: [],
    risk: "Various vulnerable library versions",
  },
  {
    domain: "code.jquery.com",
    paths: [],
    risk: "DOM-based XSS in jQuery versions < 3.5.0",
    cves: ["CVE-2020-11022", "CVE-2020-11023"],
  },
];
