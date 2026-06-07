/**
 * Main runner script: Execute full LLM vs SonarQube comparison pipeline.
 *
 * Usage:
 *     npx tsx backend/run-comparison.ts [--dataset simulated] [--output ./reports]
 *
 * This script:
 * 1. Loads vulnerability test dataset
 * 2. Exports samples to files
 * 3. Runs SonarQube analysis
 * 4. Runs LLM analysis (Opus + Sonnet)
 * 5. Evaluates and compares results
 * 6. Generates JSON report for the Web UI
 */
import { Command } from "commander";
import { DatasetManager } from "./dataset-manager";
import { runSonarQubeAnalysis } from "./sonarqube-scanner";
import { runLLMAnalysis } from "./llm-analyzer";
import { Evaluator, generateComparisonReport } from "./evaluator";
import { llmConfig } from "./config";
import * as fs from "fs/promises";
import * as path from "path";

interface Sample {
  sample_id: string;
  source_code: string;
  language: string;
  is_vulnerable: boolean;
  cwe_id: string;
  vuln_type: string;
}

function prepareSamplesForAnalysis(dm: DatasetManager): Sample[] {
  return dm.samples.map((s) => ({
    sample_id: s.sample_id,
    source_code: s.source_code,
    language: s.language,
    is_vulnerable: s.is_vulnerable,
    cwe_id: s.cwe_id,
    vuln_type: s.vuln_type,
  }));
}

async function runFullComparison(outputDir: string = "./reports"): Promise<Record<string, any>> {
  console.log("=".repeat(60));
  console.log("LLM vs SonarQube SAST Comparison Engine");
  console.log("=".repeat(60));

  // Step 1: Load dataset
  console.log("\n[1/6] Loading vulnerability dataset...");
  const dm = new DatasetManager();
  const stats = await dm.loadSimulatedDataset();
  console.log(`  Loaded ${stats.total_samples} samples`);
  console.log(`  Vulnerable: ${stats.vulnerable_count}, Safe: ${stats.safe_count}`);
  console.log(`  Languages: ${JSON.stringify(stats.language_distribution)}`);

  // Export to files
  await dm.exportToFiles();
  await dm.saveMetadata();

  // Step 2: Prepare samples
  console.log("\n[2/6] Preparing samples for analysis...");
  const samples = prepareSamplesForAnalysis(dm);

  // Step 3: Run SonarQube analysis
  console.log("\n[3/6] Running SonarQube analysis...");
  let sonarResults: Array<Record<string, any>> = [];
  try {
    sonarResults = runSonarQubeAnalysis(samples);
    const detected = sonarResults.filter((r) => r.detected).length;
    console.log(`  SonarQube detected ${detected}/${stats.vulnerable_count} vulnerabilities`);
  } catch (e) {
    console.error(`  SonarQube analysis failed: ${e}`);
  }

  // Step 4: Run LLM analysis - Claude Opus
  console.log("\n[4/6] Running Claude Opus 4.1 analysis...");
  let opusResults: Array<Record<string, any>> = [];
  try {
    const opusAnalysis = await runLLMAnalysis(
      samples,
      "claude-opus-4-1-20250819",
      llmConfig.anthropic_base_url
    );
    opusResults = opusAnalysis.map((r) => ({
      ...r,
      sample_id: r.sample_id,
      vulnerabilities_found: r.vulnerabilities_found,
      tokens_input: r.tokens_input,
      tokens_output: r.tokens_output,
      cost_usd: r.cost_usd,
      analysis_duration_ms: r.analysis_duration_ms,
    }));
    const opusDetected = opusResults.filter((r) => r.vulnerabilities_found).length;
    const opusCost = opusResults.reduce((sum, r) => sum + (r.cost_usd || 0), 0);
    console.log(`  Opus detected ${opusDetected}/${stats.vulnerable_count} vulnerabilities`);
    console.log(`  Total cost: $${opusCost.toFixed(4)}`);
  } catch (e) {
    console.error(`  Opus analysis failed: ${e}`);
  }

  // Step 5: Run LLM analysis - Claude Sonnet
  console.log("\n[5/6] Running Claude Sonnet 4 analysis...");
  let sonnetResults: Array<Record<string, any>> = [];
  try {
    const sonnetAnalysis = await runLLMAnalysis(
      samples,
      "claude-sonnet-4-20250514",
      llmConfig.anthropic_base_url
    );
    sonnetResults = sonnetAnalysis.map((r) => ({
      ...r,
      sample_id: r.sample_id,
      vulnerabilities_found: r.vulnerabilities_found,
      tokens_input: r.tokens_input,
      tokens_output: r.tokens_output,
      cost_usd: r.cost_usd,
      analysis_duration_ms: r.analysis_duration_ms,
    }));
    const sonnetDetected = sonnetResults.filter((r) => r.vulnerabilities_found).length;
    const sonnetCost = sonnetResults.reduce((sum, r) => sum + (r.cost_usd || 0), 0);
    console.log(`  Sonnet detected ${sonnetDetected}/${stats.vulnerable_count} vulnerabilities`);
    console.log(`  Total cost: $${sonnetCost.toFixed(4)}`);
  } catch (e) {
    console.error(`  Sonnet analysis failed: ${e}`);
  }

  // Step 6: Evaluate and compare
  console.log("\n[6/6] Evaluating and comparing results...");
  const evaluator = new Evaluator(samples);
  const comparison = evaluator.compareAll(sonarResults, opusResults, sonnetResults);

  // Add metadata
  const fullComparison: Record<string, any> = {
    ...comparison,
    metadata: {
      dataset_stats: {
        total_samples: stats.total_samples,
        vulnerable_count: stats.vulnerable_count,
        safe_count: stats.safe_count,
        language_distribution: stats.language_distribution,
        cwe_distribution: stats.cwe_distribution,
        vuln_type_distribution: stats.vuln_type_distribution,
      },
      models_tested: [
        "SonarQube Enterprise (simulated)",
        "Claude Opus 4.1 (simulated)",
        "Claude Sonnet 4 (simulated)",
      ],
      note:
        "This is a PoC with simulated detection results based on research findings. " +
        "For production use, configure real SonarQube and Anthropic API access.",
    },
  };

  // Save report
  await fs.mkdir(outputDir, { recursive: true });
  const reportPath = path.join(outputDir, "comparison_report.json");
  await generateComparisonReport(fullComparison, reportPath);

  // Also save individual results
  await fs.writeFile(
    path.join(outputDir, "sonarqube_results.json"),
    JSON.stringify(sonarResults, null, 2),
    "utf-8"
  );
  await fs.writeFile(
    path.join(outputDir, "opus_results.json"),
    JSON.stringify(opusResults, null, 2),
    "utf-8"
  );
  await fs.writeFile(
    path.join(outputDir, "sonnet_results.json"),
    JSON.stringify(sonnetResults, null, 2),
    "utf-8"
  );

  console.log(`\n${"=".repeat(60)}`);
  console.log("Comparison complete!");
  console.log(`Report saved to: ${reportPath}`);
  console.log("=".repeat(60));

  // Print summary
  const sq = comparison.sonarqube.overall_metrics;
  const op = comparison.claude_opus.overall_metrics;
  const sn = comparison.claude_sonnet.overall_metrics;

  console.log("\n--- SUMMARY ---");
  console.log(`${"Scanner".padEnd(20)} ${"Precision".padStart(10)} ${"Recall".padStart(10)} ${"F1".padStart(10)}`);
  console.log("-".repeat(52));
  console.log(`${"SonarQube".padEnd(20)} ${sq.precision.toFixed(4).padStart(10)} ${sq.recall.toFixed(4).padStart(10)} ${sq.f1_score.toFixed(4).padStart(10)}`);
  console.log(`${"Claude Opus 4.1".padEnd(20)} ${op.precision.toFixed(4).padStart(10)} ${op.recall.toFixed(4).padStart(10)} ${op.f1_score.toFixed(4).padStart(10)}`);
  console.log(`${"Claude Sonnet 4".padEnd(20)} ${sn.precision.toFixed(4).padStart(10)} ${sn.recall.toFixed(4).padStart(10)} ${sn.f1_score.toFixed(4).padStart(10)}`);

  return fullComparison;
}

async function main() {
  const program = new Command();
  program
    .name("sastcompare")
    .description("LLM vs SonarQube SAST Comparison Engine")
    .option("--output, -o <path>", "Output directory for reports", "./reports")
    .option("--dataset <type>", "Dataset to use", "simulated")
    .parse();

  const options = program.opts();

  // Run comparison
  await runFullComparison(options.output);

  return 0;
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
