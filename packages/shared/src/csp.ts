export type PolicySourceKind =
  | "keyword"
  | "scheme"
  | "host"
  | "nonce"
  | "hash"
  | "unsafe";

export type PolicySource = {
  value: string;
  kind: PolicySourceKind;
  isWildcard: boolean;
  isUnsafe: boolean;
};

export type PolicyDirective = {
  name: string;
  values: string[];
  isImplicit: boolean;
  sources: PolicySource[];
};

export type ParsedPolicy = {
  id: string;
  requestId: string;
  headerName: string;
  headerValue: string;
  directives: Map<string, PolicyDirective>;
  isReportOnly: boolean;
  isDeprecated: boolean;
  parsedAt: Date;
  url?: string;
};
