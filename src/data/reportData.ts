import reportJson from './comparison_report.json';
import type {
  DetectionMetrics,
  CostMetrics,
  ComparisonResult,
  SummaryData,
  DatasetStats,
  ReportData,
} from '../../backend/types';

export type {
  DetectionMetrics,
  CostMetrics,
  ComparisonResult,
  SummaryData,
  DatasetStats,
  ReportData,
};

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
