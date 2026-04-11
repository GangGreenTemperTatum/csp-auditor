type ThreatHost = {
  domain: string;
  risk: string;
  severity: string;
};

export const AI_ML_HOSTS: ThreatHost[] = [
  {
    domain: "api.openai.com",
    risk: "AI API - potential data exfiltration",
    severity: "medium",
  },
  {
    domain: "api.anthropic.com",
    risk: "AI API - potential sensitive data exposure",
    severity: "medium",
  },
  {
    domain: "huggingface.co",
    risk: "ML model hosting - code execution risks",
    severity: "medium",
  },
  {
    domain: "replicate.com",
    risk: "ML API service - data privacy concerns",
    severity: "medium",
  },
  {
    domain: "colab.research.google.com",
    risk: "Jupyter notebook execution environment",
    severity: "high",
  },
];

export const WEB3_HOSTS: ThreatHost[] = [
  {
    domain: "metamask.io",
    risk: "Wallet integration - financial transaction risks",
    severity: "high",
  },
  {
    domain: "walletconnect.org",
    risk: "Cross-wallet protocol - authentication bypass",
    severity: "high",
  },
  {
    domain: "uniswap.org",
    risk: "DeFi protocol - financial manipulation",
    severity: "high",
  },
  {
    domain: "pancakeswap.finance",
    risk: "DeFi exchange - smart contract risks",
    severity: "high",
  },
  {
    domain: "web3.storage",
    risk: "Decentralized storage - content integrity issues",
    severity: "medium",
  },
];

export const JSONP_CAPABLE_HOSTS = [
  "ajax.googleapis.com",
  "api.twitter.com",
  "graph.facebook.com",
  "api.github.com",
  "api.linkedin.com",
];
