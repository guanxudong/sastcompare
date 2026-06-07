/**
 * Shared TypeScript interfaces for the SASTCompare backend and frontend.
 */

export interface DetectionMetrics {
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  f1_score: number;
  false_positive_rate: number;
  false_negative_rate: number;
  accuracy: number;
}

export interface CostMetrics {
  total_tokens_input: number;
  total_tokens_output: number;
  total_cost_usd: number;
  avg_cost_per_sample: number;
  cost_per_vulnerability_found: number;
  analysis_duration_ms: number;
  avg_duration_ms: number;
}

export interface ComparisonResult {
  scanner_name: string;
  scanner_type: string;
  overall_metrics: DetectionMetrics;
  language_metrics: Record<string, DetectionMetrics>;
  cwe_metrics: Record<string, DetectionMetrics>;
  vuln_type_metrics: Record<string, DetectionMetrics>;
  cost_metrics?: CostMetrics;
  total_samples: number;
  vulnerable_samples: number;
  safe_samples: number;
  vulnerabilities_detected: number;
}

export interface SummaryData {
  best_f1: [string, number];
  best_recall: [string, number];
  best_precision: [string, number];
  cost_efficiency: Array<{
    scanner: string;
    total_cost: number;
    cost_per_vuln: number;
  }>;
  vulnerability_coverage: {
    sonarqube: number;
    claude_opus: number;
    claude_sonnet: number;
    total_vulnerabilities: number;
  };
}

export interface DatasetStats {
  total_samples: number;
  vulnerable_count: number;
  safe_count: number;
  language_distribution: Record<string, number>;
  cwe_distribution: Record<string, number>;
  vuln_type_distribution: Record<string, number>;
}

export interface ReportData {
  sonarqube: ComparisonResult;
  claude_opus: ComparisonResult;
  claude_sonnet: ComparisonResult;
  summary: SummaryData;
  metadata: {
    dataset_stats: DatasetStats;
    models_tested: string[];
    note: string;
  };
}

export interface VulnerabilitySample {
  sample_id: string;
  language: string;
  source_code: string;
  file_path: string;
  cwe_id: string;
  cwe_name: string;
  is_vulnerable: boolean;
  vuln_type: string;
  description: string;
  sink_line?: number;
  source_line?: number;
}

export interface LLMFinding {
  cwe_id: string;
  cwe_name: string;
  vuln_type: string;
  severity: string;
  line_number: number;
  confidence: string;
  description: string;
  remediation: string;
}

export interface LLMAnalysisResult {
  sample_id: string;
  model: string;
  vulnerabilities_found: boolean;
  findings: LLMFinding[];
  summary: string;
  analysis_duration_ms: number;
  tokens_input: number;
  tokens_output: number;
  cost_usd: number;
  timestamp: string;
}

export interface SonarQubeIssue {
  issue_key: string;
  rule: string;
  severity: string;
  component: string;
  line?: number;
  message: string;
  type: string;
  status: string;
  resolution?: string;
  effort: string;
  debt: string;
  tags: string[];
  cwe?: string;
}

export interface SonarQubeScanResult {
  project_key: string;
  analysis_id: string;
  status: string;
  issues: SonarQubeIssue[];
  metrics: Record<string, any>;
  quality_gate: Record<string, any>;
  scan_duration_ms: number;
  timestamp: string;
}
