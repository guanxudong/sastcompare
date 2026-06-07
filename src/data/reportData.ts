import reportJson from './comparison_report.json';

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

export const reportData = reportJson as unknown as ReportData;

export const scanners = [
  { key: 'sonarqube', name: 'SonarQube Enterprise', color: '#4C9AFF', type: 'rule_based' },
  { key: 'claude_opus', name: 'Claude Opus 4.1', color: '#FF6B6B', type: 'llm' },
  { key: 'claude_sonnet', name: 'Claude Sonnet 4', color: '#4ECDC4', type: 'llm' },
];

export const metricLabels: Record<string, string> = {
  precision: 'Precision',
  recall: 'Recall',
  f1_score: 'F1 Score',
  false_positive_rate: 'False Positive Rate',
  false_negative_rate: 'False Negative Rate',
  accuracy: 'Accuracy',
};
