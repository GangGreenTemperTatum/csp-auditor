export type BypassDifficulty = "easy" | "medium" | "hard";

export type BypassSource = "cspbypass" | "generic";

export type BypassRecord = {
  domain: string;
  code: string;
  technique: string;
  id: string;
};

export type CuratedBypass = {
  id: string;
  name: string;
  technique: string;
  payload: string;
  description: string;
  difficulty: BypassDifficulty;
  requirements?: string[];
  domain?: string;
  source: BypassSource;
};
