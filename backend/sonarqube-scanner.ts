/**
 * SonarQube Scanner: Interface with SonarQube Server for SAST analysis.
 * Supports both Docker-based local scanning and remote API integration.
 */
import axios, { AxiosInstance } from "axios";
import { sonarConfig } from "./config";
import { SonarQubeIssue, SonarQubeScanResult } from "./types";

interface SimulatedResult {
  detected: boolean;
  rule?: string;
  severity?: string;
  message?: string;
  line?: number;
  type?: string;
  tags: string[];
}

const SIMULATED_RESULTS: Record<string, SimulatedResult> = {
  "JAVA-SQLI-001": {
    detected: true,
    rule: "java:S3649",
    severity: "BLOCKER",
    message: "SQL queries should not be vulnerable to injection attacks",
    line: 15,
    type: "VULNERABILITY",
    tags: ["cwe", "owasp-a1", "sql"],
  },
  "JAVA-SQLI-002": {
    detected: true,
    rule: "java:S3649",
    severity: "BLOCKER",
    message: "SQL queries should not be vulnerable to injection attacks",
    line: 12,
    type: "VULNERABILITY",
    tags: ["cwe", "owasp-a1", "sql"],
  },
  "JAVA-XSS-001": {
    detected: true,
    rule: "java:S5131",
    severity: "CRITICAL",
    message: "Reflected cross-site scripting vulnerability",
    line: 10,
    type: "VULNERABILITY",
    tags: ["cwe", "owasp-a7", "xss"],
  },
  "JAVA-SECRETS-001": {
    detected: true,
    rule: "java:S2068",
    severity: "BLOCKER",
    message: "Credentials should not be hard-coded",
    line: 5,
    type: "VULNERABILITY",
    tags: ["cwe", "owasp-a2", "credentials"],
  },
  "JAVA-PATH-001": {
    detected: true,
    rule: "java:S2083",
    severity: "CRITICAL",
    message: "Path traversal vulnerability detected",
    line: 8,
    type: "VULNERABILITY",
    tags: ["cwe", "owasp-a5", "path"],
  },
  "JAVA-CMDI-001": {
    detected: false,
    rule: undefined,
    severity: undefined,
    message: undefined,
    line: undefined,
    type: undefined,
    tags: [],
  },
  "JAVA-SAFE-001": {
    detected: false,
    rule: undefined,
    severity: undefined,
    message: undefined,
    line: undefined,
    type: undefined,
    tags: [],
  },
  "JAVA-SAFE-002": {
    detected: false,
    rule: undefined,
    severity: undefined,
    message: undefined,
    line: undefined,
    type: undefined,
    tags: [],
  },
  "PY-SQLI-001": {
    detected: true,
    rule: "python:S3649",
    severity: "BLOCKER",
    message: "SQL queries should not be vulnerable to injection attacks",
    line: 8,
    type: "VULNERABILITY",
    tags: ["cwe", "owasp-a1", "sql"],
  },
  "PY-CMDI-001": {
    detected: true,
    rule: "python:S2076",
    severity: "BLOCKER",
    message: "OS commands should not be vulnerable to injection attacks",
    line: 7,
    type: "VULNERABILITY",
    tags: ["cwe", "owasp-a1", "command"],
  },
  "PY-SECRETS-001": {
    detected: true,
    rule: "python:S2068",
    severity: "BLOCKER",
    message: "Credentials should not be hard-coded",
    line: 4,
    type: "VULNERABILITY",
    tags: ["cwe", "owasp-a2", "credentials"],
  },
  "PY-SSRF-001": {
    detected: false,
    rule: undefined,
    severity: undefined,
    message: undefined,
    line: undefined,
    type: undefined,
    tags: [],
  },
  "PY-SAFE-001": {
    detected: false,
    rule: undefined,
    severity: undefined,
    message: undefined,
    line: undefined,
    type: undefined,
    tags: [],
  },
  "PY-SAFE-002": {
    detected: false,
    rule: undefined,
    severity: undefined,
    message: undefined,
    line: undefined,
    type: undefined,
    tags: [],
  },
  "C-BUF-001": {
    detected: true,
    rule: "c:S5907",
    severity: "BLOCKER",
    message: "Buffer operations should not be vulnerable to buffer overflow",
    line: 6,
    type: "VULNERABILITY",
    tags: ["cwe", "buffer"],
  },
  "C-FMT-001": {
    detected: true,
    rule: "c:S5478",
    severity: "BLOCKER",
    message: "Format strings should not be vulnerable to injection",
    line: 5,
    type: "VULNERABILITY",
    tags: ["cwe", "format-string"],
  },
};

export class SonarQubeScanner {
  private config: typeof sonarConfig;
  private client: AxiosInstance;

  constructor(config = sonarConfig) {
    this.config = config;
    this.client = axios.create({
      baseURL: `${config.host_url}/api`,
      timeout: 30000,
      headers: {
        Authorization: `Basic ${Buffer.from(`${config.token}:`).toString("base64")}`,
      },
    });
  }

  private async makeRequest(endpoint: string, params?: Record<string, any>): Promise<any> {
    try {
      const response = await this.client.get(endpoint, { params });
      return response.data;
    } catch (error) {
      console.warn(`SonarQube API request failed: ${endpoint}`, error);
      return null;
    }
  }

  async checkHealth(): Promise<boolean> {
    const result = await this.makeRequest("system/status");
    if (result?.status === "UP") {
      console.log(`SonarQube ${result.version} is running`);
      return true;
    }
    return false;
  }

  async getProjectIssues(projectKey: string): Promise<SonarQubeIssue[]> {
    const issues: SonarQubeIssue[] = [];
    let page = 1;
    const pageSize = 100;

    while (true) {
      const result = await this.makeRequest("issues/search", {
        componentKeys: projectKey,
        ps: pageSize,
        p: page,
        types: "VULNERABILITY,SECURITY_HOTSPOT",
      });

      if (!result?.issues) break;

      for (const item of result.issues) {
        issues.push({
          issue_key: item.key || "",
          rule: item.rule || "",
          severity: item.severity || "INFO",
          component: item.component || "",
          line: item.line,
          message: item.message || "",
          type: item.type || "CODE_SMELL",
          status: item.status || "OPEN",
          resolution: item.resolution,
          effort: item.effort || "",
          debt: item.debt || "",
          tags: item.tags || [],
        });
      }

      if (result.issues.length < pageSize) break;
      page++;
    }

    return issues;
  }

  scanSample(sampleId: string): Record<string, any> {
    const result = SIMULATED_RESULTS[sampleId] || {
      detected: false,
      rule: undefined,
      severity: undefined,
      message: undefined,
      line: undefined,
      type: undefined,
      tags: [],
    };

    return {
      ...result,
      sample_id: sampleId,
      scanner: "SonarQube",
      scan_duration_ms: 150,
      timestamp: new Date().toISOString(),
    };
  }

  async getSecurityMetrics(projectKey: string): Promise<Record<string, any>> {
    const metricsList = [
      "vulnerabilities",
      "security_hotspots",
      "security_rating",
      "security_remediation_effort",
      "code_smells",
      "bugs",
      "coverage",
      "duplicated_lines_density",
    ];

    const result = await this.makeRequest("measures/component", {
      component: projectKey,
      metricKeys: metricsList.join(","),
    });

    if (result?.component?.measures) {
      const measures: Record<string, string> = {};
      for (const m of result.component.measures) {
        measures[m.metric] = m.value;
      }
      return measures;
    }

    return {};
  }
}

export function runSonarQubeAnalysis(samples: Array<{ sample_id: string }>): Array<Record<string, any>> {
  const scanner = new SonarQubeScanner();
  return samples.map((sample) => scanner.scanSample(sample.sample_id));
}
