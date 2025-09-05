// Global types for Node.js environment
declare global {
  class URL {
    constructor(input: string, base?: string | URL);
    readonly hostname: string;
    readonly protocol: string;
    readonly host: string;
    readonly pathname: string;
  }
}

export {};
