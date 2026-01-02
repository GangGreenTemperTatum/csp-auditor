// CSP bypass database - uses generated data from data/csp-bypass-data.tsv
// The data is inlined at build time via scripts/generate-bypass-data.js

import { CSP_BYPASS_TSV_DATA, BYPASS_ENTRY_COUNT } from "./bypass-data.generated";

export const getCSPBypassData = (): string => {
  return CSP_BYPASS_TSV_DATA;
};

export const getBypassCount = (): number => {
  return BYPASS_ENTRY_COUNT;
};

// Legacy exports for backward compatibility
export const CSP_BYPASS_DATA = CSP_BYPASS_TSV_DATA;
export const BYPASS_COUNT = BYPASS_ENTRY_COUNT;
