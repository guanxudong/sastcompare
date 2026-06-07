/**
 * Evaluator: Compare LLM and SonarQube detection results.
 * Computes precision, recall, F1, false positive/negative rates, and cost metrics.
 */
import * as fs from "fs/promises";
import * as path from "path";
import { DetectionMetrics, CostMetrics, ComparisonResult, SummaryData } from "./types";

export class Evaluator {
  private groundTruth: Record<string, any>;
  private samples: Array<Record<string, any>>;

  constructor(groundTruth: Array<Record<string, any>>) {
    this.groundTruth = {};
    for (const s of groundTruth) {
      this.groundTruth[s.sample_id] = s;
    }
    this.samples = groundTruth;
  }

  private createMetrics(): DetectionMetrics {
    return {
      true_positives: 0,
      false_positives: 0,
      true_negatives: 0,
      false_negatives: 0,
      precision: 0,
      recall: 0,
      f1_score: 0,
      false_positive_rate: 0,
      false_negative_rate: 0,
      accuracy: 0,
    };
  }

  private calculateMetrics(m: DetectionMetrics): DetectionMetrics {
    const tp = m.true_positives;
    const fp = m.false_positives;
    const tn = m.true_negatives;
    const fn = m.false_negatives;

    const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
    const recall = tp + fn === 0 ? 0 : tp / (tp + fn);
    const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
    const fpr = fp + tn === 0 ? 0 : fp / (fp + tn);
    const fnr = fn + tp === 0 ? 0 : fn / (fn + tp);
    const total = tp + tn + fp + fn;
    const accuracy = total === 0 ? 0 : (tp + tn) / total;

    return {
      true_positives: tp,
      false_positives: fp,
      true_negatives: tn,
      false_negatives: fn,
      precision: Math.round(precision * 10000) / 10000,
      recall: Math.round(recall * 10000) / 10000,
      f1_score: Math.round(f1 * 10000) / 10000,
      false_positive_rate: Math.round(fpr * 10000) / 10000,
      false_negative_rate: Math.round(fnr * 10000) / 10000,
      accuracy: Math.round(accuracy * 10000) / 10000,
    };
  }

  evaluateSonarQube(sonarResults: Array<Record<string, any>>): ComparisonResult {
    const result: ComparisonResult = {
      scanner_name: "SonarQube Enterprise",
      scanner_type: "rule_based",
      overall_metrics: this.createMetrics(),
      language_metrics: {},
      cwe_metrics: {},
      vuln_type_metrics: {},
      total_samples: 0,
      vulnerable_samples: 0,
      safe_samples: 0,
      vulnerabilities_detected: 0,
    };

    const sonarById: Record<string, any> = {};
    for (const r of sonarResults) {
      sonarById[r.sample_id] = r;
    }

    const langMetrics: Record<string, DetectionMetrics> = {};
    const cweMetrics: Record<string, DetectionMetrics> = {};
    const vulnMetrics: Record<string, DetectionMetrics> = {};
    const overall = this.createMetrics();

    let vulnerabilitiesFound = 0;

    for (const sample of this.samples) {
      const sid = sample.sample_id;
      const gtVulnerable = sample.is_vulnerable;

      const sonarResult = sonarById[sid] || {};
      const detected = sonarResult.detected || false;

      const lang = sample.language;
      const cwe = sample.cwe_id;
      const vtype = sample.vuln_type;

      if (!langMetrics[lang]) langMetrics[lang] = this.createMetrics();
      if (!cweMetrics[cwe]) cweMetrics[cwe] = this.createMetrics();
      if (!vulnMetrics[vtype]) vulnMetrics[vtype] = this.createMetrics();

      if (gtVulnerable && detected) {
        overall.true_positives++;
        langMetrics[lang].true_positives++;
        cweMetrics[cwe].true_positives++;
        vulnMetrics[vtype].true_positives++;
        vulnerabilitiesFound++;
      } else if (!gtVulnerable && detected) {
        overall.false_positives++;
        langMetrics[lang].false_positives++;
        cweMetrics[cwe].false_positives++;
        vulnMetrics[vtype].false_positives++;
      } else if (!gtVulnerable && !detected) {
        overall.true_negatives++;
        langMetrics[lang].true_negatives++;
        cweMetrics[cwe].true_negatives++;
        vulnMetrics[vtype].true_negatives++;
      } else {
        overall.false_negatives++;
        langMetrics[lang].false_negatives++;
        cweMetrics[cwe].false_negatives++;
        vulnMetrics[vtype].false_negatives++;
      }
    }

    result.overall_metrics = this.calculateMetrics(overall);
    result.language_metrics = Object.fromEntries(
      Object.entries(langMetrics).map(([k, v]) => [k, this.calculateMetrics(v)])
    );
    result.cwe_metrics = Object.fromEntries(
      Object.entries(cweMetrics).map(([k, v]) => [k, this.calculateMetrics(v)])
    );
    result.vuln_type_metrics = Object.fromEntries(
      Object.entries(vulnMetrics).map(([k, v]) => [k, this.calculateMetrics(v)])
    );
    result.total_samples = this.samples.length;
    result.vulnerable_samples = this.samples.filter((s) => s.is_vulnerable).length;
    result.safe_samples = result.total_samples - result.vulnerable_samples;
    result.vulnerabilities_detected = vulnerabilitiesFound;

    return result;
  }

  evaluateLLM(llmResults: Array<Record<string, any>>, modelName: string): ComparisonResult {
    const result: ComparisonResult = {
      scanner_name: modelName,
      scanner_type: "llm",
      overall_metrics: this.createMetrics(),
      language_metrics: {},
      cwe_metrics: {},
      vuln_type_metrics: {},
      total_samples: 0,
      vulnerable_samples: 0,
      safe_samples: 0,
      vulnerabilities_detected: 0,
    };

    const llmById: Record<string, any> = {};
    for (const r of llmResults) {
      llmById[r.sample_id] = r;
    }

    const langMetrics: Record<string, DetectionMetrics> = {};
    const cweMetrics: Record<string, DetectionMetrics> = {};
    const vulnMetrics: Record<string, DetectionMetrics> = {};
    const overall = this.createMetrics();

    const cost: CostMetrics = {
      total_tokens_input: 0,
      total_tokens_output: 0,
      total_cost_usd: 0,
      avg_cost_per_sample: 0,
      cost_per_vulnerability_found: 0,
      analysis_duration_ms: 0,
      avg_duration_ms: 0,
    };

    let vulnerabilitiesFound = 0;

    for (const sample of this.samples) {
      const sid = sample.sample_id;
      const gtVulnerable = sample.is_vulnerable;

      const llmResult = llmById[sid] || {};
      const detected = llmResult.vulnerabilities_found || false;

      const lang = sample.language;
      const cwe = sample.cwe_id;
      const vtype = sample.vuln_type;

      if (!langMetrics[lang]) langMetrics[lang] = this.createMetrics();
      if (!cweMetrics[cwe]) cweMetrics[cwe] = this.createMetrics();
      if (!vulnMetrics[vtype]) vulnMetrics[vtype] = this.createMetrics();

      if (llmResult.tokens_input) cost.total_tokens_input += llmResult.tokens_input;
      if (llmResult.tokens_output) cost.total_tokens_output += llmResult.tokens_output;
      if (llmResult.cost_usd) cost.total_cost_usd += llmResult.cost_usd;
      if (llmResult.analysis_duration_ms) cost.analysis_duration_ms += llmResult.analysis_duration_ms;

      if (gtVulnerable && detected) {
        overall.true_positives++;
        langMetrics[lang].true_positives++;
        cweMetrics[cwe].true_positives++;
        vulnMetrics[vtype].true_positives++;
        vulnerabilitiesFound++;
      } else if (!gtVulnerable && detected) {
        overall.false_positives++;
        langMetrics[lang].false_positives++;
        cweMetrics[cwe].false_positives++;
        vulnMetrics[vtype].false_positives++;
      } else if (!gtVulnerable && !detected) {
        overall.true_negatives++;
        langMetrics[lang].true_negatives++;
        cweMetrics[cwe].true_negatives++;
        vulnMetrics[vtype].true_negatives++;
      } else {
        overall.false_negatives++;
        langMetrics[lang].false_negatives++;
        cweMetrics[cwe].false_negatives++;
        vulnMetrics[vtype].false_negatives++;
      }
    }

    if (result.total_samples > 0) {
      cost.avg_cost_per_sample = cost.total_cost_usd / result.total_samples;
      cost.avg_duration_ms = cost.analysis_duration_ms / result.total_samples;
    }
    if (vulnerabilitiesFound > 0) {
      cost.cost_per_vulnerability_found = cost.total_cost_usd / vulnerabilitiesFound;
    }

    result.overall_metrics = this.calculateMetrics(overall);
    result.language_metrics = Object.fromEntries(
      Object.entries(langMetrics).map(([k, v]) => [k, this.calculateMetrics(v)])
    );
    result.cwe_metrics = Object.fromEntries(
      Object.entries(cweMetrics).map(([k, v]) => [k, this.calculateMetrics(v)])
    );
    result.vuln_type_metrics = Object.fromEntries(
      Object.entries(vulnMetrics).map(([k, v]) => [k, this.calculateMetrics(v)])
    );
    result.cost_metrics = cost;
    result.total_samples = this.samples.length;
    result.vulnerable_samples = this.samples.filter((s) => s.is_vulnerable).length;
    result.safe_samples = result.total_samples - result.vulnerable_samples;
    result.vulnerabilities_detected = vulnerabilitiesFound;

    return result;
  }

  compareAll(
    sonarResults: Array<Record<string, any>>,
    llmOpusResults: Array<Record<string, any>>,
    llmSonnetResults: Array<Record<string, any>>
  ): {
    sonarqube: ComparisonResult;
    claude_opus: ComparisonResult;
    claude_sonnet: ComparisonResult;
    summary: SummaryData;
  } {
    const sonarEval = this.evaluateSonarQube(sonarResults);
    const opusEval = this.evaluateLLM(llmOpusResults, "Claude Opus 4.1");
    const sonnetEval = this.evaluateLLM(llmSonnetResults, "Claude Sonnet 4");

    return {
      sonarqube: sonarEval,
      claude_opus: opusEval,
      claude_sonnet: sonnetEval,
      summary: this.generateSummary(sonarEval, opusEval, sonnetEval),
    };
  }

  private generateSummary(
    sonar: ComparisonResult,
    opus: ComparisonResult,
    sonnet: ComparisonResult
  ): SummaryData {
    const metrics = [
      ["SonarQube", sonar.overall_metrics.f1_score],
      ["Claude Opus 4.1", opus.overall_metrics.f1_score],
      ["Claude Sonnet 4", sonnet.overall_metrics.f1_score],
    ] as [string, number][];

    const recalls = [
      ["SonarQube", sonar.overall_metrics.recall],
      ["Claude Opus 4.1", opus.overall_metrics.recall],
      ["Claude Sonnet 4", sonnet.overall_metrics.recall],
    ] as [string, number][];

    const precisions = [
      ["SonarQube", sonar.overall_metrics.precision],
      ["Claude Opus 4.1", opus.overall_metrics.precision],
      ["Claude Sonnet 4", sonnet.overall_metrics.precision],
    ] as [string, number][];

    const bestF1 = metrics.reduce((a, b) => (a[1] > b[1] ? a : b));
    const bestRecall = recalls.reduce((a, b) => (a[1] > b[1] ? a : b));
    const bestPrecision = precisions.reduce((a, b) => (a[1] > b[1] ? a : b));

    return {
      best_f1: bestF1,
      best_recall: bestRecall,
      best_precision: bestPrecision,
      cost_efficiency: [
        {
          scanner: "Claude Opus 4.1",
          total_cost: opus.cost_metrics?.total_cost_usd || 0,
          cost_per_vuln: opus.cost_metrics?.cost_per_vulnerability_found || 0,
        },
        {
          scanner: "Claude Sonnet 4",
          total_cost: sonnet.cost_metrics?.total_cost_usd || 0,
          cost_per_vuln: sonnet.cost_metrics?.cost_per_vulnerability_found || 0,
        },
      ],
      vulnerability_coverage: {
        sonarqube: sonar.vulnerabilities_detected,
        claude_opus: opus.vulnerabilities_detected,
        claude_sonnet: sonnet.vulnerabilities_detected,
        total_vulnerabilities: sonar.vulnerable_samples,
      },
    };
  }
}

export async function generateComparisonReport(
  comparison: Record<string, any>,
  outputPath: string = "./reports/comparison_report.json"
): Promise<void> {
  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, JSON.stringify(comparison, null, 2), "utf-8");
  console.log(`Comparison report saved to ${outputPath}`);
}
