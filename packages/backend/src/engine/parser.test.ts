import { extractCspHeaders, parsePolicyHeader } from "./parser";

describe("extractCspHeaders", () => {
  it("extracts standard CSP header", () => {
    const headers = { "Content-Security-Policy": "default-src 'self'" };
    const result = extractCspHeaders(headers);
    expect(result).toHaveLength(1);
    expect(result[0]!.name).toBe("content-security-policy");
    expect(result[0]!.value).toBe("default-src 'self'");
  });

  it("extracts report-only header", () => {
    const headers = {
      "Content-Security-Policy-Report-Only": "default-src 'none'",
    };
    const result = extractCspHeaders(headers);
    expect(result).toHaveLength(1);
    expect(result[0]!.name).toBe("content-security-policy-report-only");
  });

  it("extracts deprecated headers", () => {
    const headers = { "X-Content-Security-Policy": "default-src 'self'" };
    const result = extractCspHeaders(headers);
    expect(result).toHaveLength(1);
    expect(result[0]!.name).toBe("x-content-security-policy");
  });

  it("handles string array header values", () => {
    const headers = {
      "Content-Security-Policy": ["default-src 'self'", "script-src 'none'"],
    };
    const result = extractCspHeaders(headers);
    expect(result).toHaveLength(2);
  });

  it("skips non-CSP headers", () => {
    const headers = { "X-Frame-Options": "DENY", "Content-Type": "text/html" };
    const result = extractCspHeaders(headers);
    expect(result).toHaveLength(0);
  });

  it("returns empty for no headers", () => {
    const result = extractCspHeaders({});
    expect(result).toHaveLength(0);
  });

  it("trims whitespace from values", () => {
    const headers = { "Content-Security-Policy": "  default-src 'self'  " };
    const result = extractCspHeaders(headers);
    expect(result[0]!.value).toBe("default-src 'self'");
  });
});

describe("parsePolicyHeader", () => {
  it("parses single directive", () => {
    const policy = parsePolicyHeader(
      "content-security-policy",
      "default-src 'self'",
      "req-1",
    );
    expect(policy.directives.has("default-src")).toBe(true);
    expect(policy.directives.get("default-src")!.values).toEqual(["'self'"]);
  });

  it("parses multiple directives", () => {
    const policy = parsePolicyHeader(
      "content-security-policy",
      "script-src 'none'; style-src 'unsafe-inline'; img-src 'self'",
      "req-1",
    );
    expect(policy.directives.size).toBe(3);
    expect(policy.directives.has("script-src")).toBe(true);
    expect(policy.directives.has("style-src")).toBe(true);
    expect(policy.directives.has("img-src")).toBe(true);
  });

  it("classifies keyword sources", () => {
    const policy = parsePolicyHeader(
      "content-security-policy",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'none'",
      "req-1",
    );
    const scriptSrc = policy.directives.get("script-src")!;
    expect(scriptSrc.sources).toHaveLength(4);
    expect(scriptSrc.sources[0]!.kind).toBe("keyword");
    expect(scriptSrc.sources[1]!.isUnsafe).toBe(true);
    expect(scriptSrc.sources[2]!.isUnsafe).toBe(true);
  });

  it("classifies nonce sources", () => {
    const policy = parsePolicyHeader(
      "content-security-policy",
      "script-src 'nonce-abc123'",
      "req-1",
    );
    const source = policy.directives.get("script-src")!.sources[0]!;
    expect(source.kind).toBe("nonce");
    expect(source.value).toBe("'nonce-abc123'");
  });

  it("classifies hash sources", () => {
    const policy = parsePolicyHeader(
      "content-security-policy",
      "script-src 'sha256-abc123'",
      "req-1",
    );
    const source = policy.directives.get("script-src")!.sources[0]!;
    expect(source.kind).toBe("hash");
  });

  it("classifies host sources", () => {
    const policy = parsePolicyHeader(
      "content-security-policy",
      "script-src cdn.example.com *.example.com",
      "req-1",
    );
    const sources = policy.directives.get("script-src")!.sources;
    expect(sources[0]!.kind).toBe("host");
    expect(sources[0]!.isWildcard).toBe(false);
    expect(sources[1]!.kind).toBe("host");
    expect(sources[1]!.isWildcard).toBe(true);
  });

  it("marks deprecated headers", () => {
    const policy = parsePolicyHeader(
      "x-webkit-csp",
      "default-src 'self'",
      "req-1",
    );
    expect(policy.isDeprecated).toBe(true);
  });

  it("marks report-only headers", () => {
    const policy = parsePolicyHeader(
      "content-security-policy-report-only",
      "default-src 'self'",
      "req-1",
    );
    expect(policy.isReportOnly).toBe(true);
  });

  it("applies default-src fallbacks", () => {
    const policy = parsePolicyHeader(
      "content-security-policy",
      "default-src 'self' cdn.example.com",
      "req-1",
    );
    expect(policy.directives.has("script-src")).toBe(true);
    expect(policy.directives.has("style-src")).toBe(true);
    expect(policy.directives.has("img-src")).toBe(true);
    const scriptSrc = policy.directives.get("script-src")!;
    expect(scriptSrc.isImplicit).toBe(true);
    expect(scriptSrc.values).toEqual(["'self'", "cdn.example.com"]);
  });

  it("does not override explicit directives with default-src", () => {
    const policy = parsePolicyHeader(
      "content-security-policy",
      "default-src 'self'; script-src 'none'",
      "req-1",
    );
    const scriptSrc = policy.directives.get("script-src")!;
    expect(scriptSrc.isImplicit).toBe(false);
    expect(scriptSrc.values).toEqual(["'none'"]);
  });
});
