import {
  isUserContentHost,
  isVulnerableJsHost,
  stripDomainPrefix,
} from "./domainMatching";

describe("stripDomainPrefix", () => {
  it("strips https:// protocol", () => {
    expect(stripDomainPrefix("https://example.com/path")).toBe("example.com");
  });

  it("strips http:// protocol", () => {
    expect(stripDomainPrefix("http://example.com")).toBe("example.com");
  });

  it("strips path after domain", () => {
    expect(stripDomainPrefix("example.com/foo/bar")).toBe("example.com");
  });

  it("lowercases domain", () => {
    expect(stripDomainPrefix("EXAMPLE.COM")).toBe("example.com");
  });
});

describe("isUserContentHost", () => {
  it("matches exact domain", () => {
    expect(isUserContentHost("github.com")).toBe(true);
  });

  it("matches wildcard pattern", () => {
    expect(isUserContentHost("test.github.io")).toBe(true);
  });

  it("returns false for non-matching domain", () => {
    expect(isUserContentHost("example.com")).toBe(false);
  });
});

describe("isVulnerableJsHost", () => {
  it("matches domain with empty paths", () => {
    const result = isVulnerableJsHost("cdn.jsdelivr.net");
    expect(result.isVulnerable).toBe(true);
  });

  it("matches domain with matching path", () => {
    const result = isVulnerableJsHost(
      "cdnjs.cloudflare.com",
      "/ajax/libs/angular.js/1.6.0/angular.js",
    );
    expect(result.isVulnerable).toBe(true);
    expect(result.risk).toBeDefined();
  });

  it("matches subdomain", () => {
    const result = isVulnerableJsHost("sub.cdn.jsdelivr.net");
    expect(result.isVulnerable).toBe(true);
  });

  it("returns false for safe domain", () => {
    const result = isVulnerableJsHost("example.com");
    expect(result.isVulnerable).toBe(false);
  });
});
