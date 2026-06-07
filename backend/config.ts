/**
 * Configuration for the LLM vs SonarQube SAST Comparison Engine.
 */

export interface SonarQubeConfig {
  host_url: string;
  token: string;
  project_key: string;
}

export interface LLMConfig {
  anthropic_api_key: string;
  anthropic_base_url: string;
  anthropic_api_version: string;
  model_opus: string;
  model_sonnet: string;
  model_haiku: string;
  max_tokens: number;
  temperature: number;
  pricing: Record<string, { input: number; output: number; cached: number }>;
}

export interface DatasetConfig {
  base_path: string;
  sources: Record<string, {
    name: string;
    url: string;
    languages: string[];
    test_cases: number;
    description: string;
  }>;
}

export interface EvaluationConfig {
  metrics: string[];
  cwe_categories: string[];
  vuln_types: string[];
}

function getEnv(key: string, defaultValue: string): string {
  return process.env[key] || defaultValue;
}

export const sonarConfig: SonarQubeConfig = {
  host_url: getEnv("SONAR_HOST_URL", "http://localhost:9000"),
  token: getEnv("SONAR_TOKEN", ""),
  project_key: getEnv("SONAR_PROJECT_KEY", "llm-comparison-poc"),
};

export const llmConfig: LLMConfig = {
  anthropic_api_key: getEnv("ANTHROPIC_API_KEY", ""),
  anthropic_base_url: getEnv("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
  anthropic_api_version: "2023-06-01",
  model_opus: "claude-opus-4-1-20250819",
  model_sonnet: "claude-sonnet-4-20250514",
  model_haiku: "claude-haiku-4-20250514",
  max_tokens: 4096,
  temperature: 0.1,
  pricing: {
    "claude-opus-4-1-20250819": { input: 5.00, output: 25.00, cached: 0.50 },
    "claude-sonnet-4-20250514": { input: 3.00, output: 15.00, cached: 0.30 },
    "claude-haiku-4-20250514": { input: 1.00, output: 5.00, cached: 0.10 },
  },
};

export const datasetConfig: DatasetConfig = {
  base_path: "./datasets",
  sources: {
    owasp_benchmark: {
      name: "OWASP Benchmark",
      url: "https://github.com/OWASP/Benchmark",
      languages: ["Java"],
      test_cases: 21041,
      description: "Java test suite for SAST accuracy evaluation",
    },
    juliet_java: {
      name: "Juliet Test Suite (Java)",
      url: "https://samate.nist.gov/SARD/test-suites/109",
      languages: ["Java"],
      test_cases: 28881,
      description: "NIST SARD Java test cases covering 112 CWEs",
    },
    juliet_cpp: {
      name: "Juliet Test Suite (C/C++)",
      url: "https://samate.nist.gov/SARD/test-suites/116",
      languages: ["C", "C++"],
      test_cases: 64099,
      description: "NIST SARD C/C++ test cases covering 112 CWEs",
    },
    securityeval: {
      name: "SecurityEval",
      url: "https://github.com/VulnExpo/SecurityEval",
      languages: ["Python"],
      test_cases: 130,
      description: "Python vulnerability samples for LLM evaluation",
    },
  },
};

export const evalConfig: EvaluationConfig = {
  metrics: [
    "precision",
    "recall",
    "f1_score",
    "false_positive_rate",
    "false_negative_rate",
    "true_positive_rate",
  ],
  cwe_categories: [
    "CWE-79",
    "CWE-89",
    "CWE-22",
    "CWE-78",
    "CWE-94",
    "CWE-862",
    "CWE-863",
    "CWE-20",
    "CWE-200",
    "CWE-502",
  ],
  vuln_types: [
    "SQL Injection",
    "XSS",
    "Path Traversal",
    "Command Injection",
    "Code Injection",
    "Insecure Deserialization",
    "Hardcoded Secrets",
    "Insecure Direct Object Reference",
    "Security Misconfiguration",
  ],
};
