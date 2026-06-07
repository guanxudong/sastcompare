"""
Main runner script: Execute full LLM vs SonarQube comparison pipeline.

Usage:
    python run_comparison.py [--dataset simulated] [--output ./reports]

This script:
1. Loads vulnerability test dataset
2. Exports samples to files
3. Runs SonarQube analysis
4. Runs LLM analysis (Opus + Sonnet)
5. Evaluates and compares results
6. Generates JSON report for the Web UI
"""
import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Any

# Add engine to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dataset_manager import DatasetManager
from sonarqube_scanner import SonarQubeScanner, run_sonarqube_analysis
from llm_analyzer import LLMAnalyzer, run_llm_analysis
from evaluator import Evaluator, generate_comparison_report

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def prepare_samples_for_analysis(dm: DatasetManager) -> List[Dict]:
    """Convert dataset samples to analysis-ready format."""
    samples = []
    for s in dm.samples:
        samples.append({
            "sample_id": s.sample_id,
            "source_code": s.source_code,
            "language": s.language,
            "is_vulnerable": s.is_vulnerable,
            "cwe_id": s.cwe_id,
            "vuln_type": s.vuln_type
        })
    return samples


def run_full_comparison(output_dir: str = "./reports") -> Dict[str, Any]:
    """Execute the complete comparison pipeline.
    
    Returns:
        Dictionary containing all comparison results
    """
    logger.info("=" * 60)
    logger.info("LLM vs SonarQube SAST Comparison Engine")
    logger.info("=" * 60)
    
    # Step 1: Load dataset
    logger.info("\n[1/6] Loading vulnerability dataset...")
    dm = DatasetManager()
    stats = dm.load_simulated_dataset()
    logger.info(f"  Loaded {stats.total_samples} samples")
    logger.info(f"  Vulnerable: {stats.vulnerable_count}, Safe: {stats.safe_count}")
    logger.info(f"  Languages: {stats.language_distribution}")
    
    # Export to files
    dm.export_to_files()
    dm.save_metadata()
    
    # Step 2: Prepare samples
    logger.info("\n[2/6] Preparing samples for analysis...")
    samples = prepare_samples_for_analysis(dm)
    
    # Step 3: Run SonarQube analysis
    logger.info("\n[3/6] Running SonarQube analysis...")
    try:
        sonar_results = run_sonarqube_analysis(samples)
        detected = sum(1 for r in sonar_results if r.get("detected"))
        logger.info(f"  SonarQube detected {detected}/{stats.vulnerable_count} vulnerabilities")
    except Exception as e:
        logger.error(f"  SonarQube analysis failed: {e}")
        sonar_results = []
    
    # Step 4: Run LLM analysis - Claude Opus
    logger.info("\n[4/6] Running Claude Opus 4.1 analysis...")
    try:
        opus_results = run_llm_analysis(samples, model="claude-opus-4-1-20250819")
        opus_detected = sum(1 for r in opus_results if r.get("vulnerabilities_found"))
        opus_cost = sum(r.get("cost_usd", 0) for r in opus_results)
        logger.info(f"  Opus detected {opus_detected}/{stats.vulnerable_count} vulnerabilities")
        logger.info(f"  Total cost: ${opus_cost:.4f}")
    except Exception as e:
        logger.error(f"  Opus analysis failed: {e}")
        opus_results = []
    
    # Step 5: Run LLM analysis - Claude Sonnet
    logger.info("\n[5/6] Running Claude Sonnet 4 analysis...")
    try:
        sonnet_results = run_llm_analysis(samples, model="claude-sonnet-4-20250514")
        sonnet_detected = sum(1 for r in sonnet_results if r.get("vulnerabilities_found"))
        sonnet_cost = sum(r.get("cost_usd", 0) for r in sonnet_results)
        logger.info(f"  Sonnet detected {sonnet_detected}/{stats.vulnerable_count} vulnerabilities")
        logger.info(f"  Total cost: ${sonnet_cost:.4f}")
    except Exception as e:
        logger.error(f"  Sonnet analysis failed: {e}")
        sonnet_results = []
    
    # Step 6: Evaluate and compare
    logger.info("\n[6/6] Evaluating and comparing results...")
    evaluator = Evaluator(samples)
    comparison = evaluator.compare_all(sonar_results, opus_results, sonnet_results)
    
    # Add metadata
    comparison["metadata"] = {
        "dataset_stats": {
            "total_samples": stats.total_samples,
            "vulnerable_count": stats.vulnerable_count,
            "safe_count": stats.safe_count,
            "language_distribution": stats.language_distribution,
            "cwe_distribution": stats.cwe_distribution,
            "vuln_type_distribution": stats.vuln_type_distribution
        },
        "models_tested": [
            "SonarQube Enterprise (simulated)",
            "Claude Opus 4.1 (simulated)",
            "Claude Sonnet 4 (simulated)"
        ],
        "note": "This is a PoC with simulated detection results based on research findings. " +
                "For production use, configure real SonarQube and Anthropic API access."
    }
    
    # Save report
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "comparison_report.json")
    generate_comparison_report(comparison, report_path)
    
    # Also save individual results
    with open(os.path.join(output_dir, "sonarqube_results.json"), 'w') as f:
        json.dump(sonar_results, f, indent=2)
    with open(os.path.join(output_dir, "opus_results.json"), 'w') as f:
        json.dump(opus_results, f, indent=2)
    with open(os.path.join(output_dir, "sonnet_results.json"), 'w') as f:
        json.dump(sonnet_results, f, indent=2)
    
    logger.info(f"\n{'=' * 60}")
    logger.info("Comparison complete!")
    logger.info(f"Report saved to: {report_path}")
    logger.info("=" * 60)
    
    # Print summary
    sq = comparison["sonarqube"]["overall_metrics"]
    op = comparison["claude_opus"]["overall_metrics"]
    sn = comparison["claude_sonnet"]["overall_metrics"]
    
    logger.info("\n--- SUMMARY ---")
    logger.info(f"{'Scanner':<20} {'Precision':>10} {'Recall':>10} {'F1':>10}")
    logger.info(f"{'-'*52}")
    logger.info(f"{'SonarQube':<20} {sq['precision']:>10.4f} {sq['recall']:>10.4f} {sq['f1_score']:>10.4f}")
    logger.info(f"{'Claude Opus 4.1':<20} {op['precision']:>10.4f} {op['recall']:>10.4f} {op['f1_score']:>10.4f}")
    logger.info(f"{'Claude Sonnet 4':<20} {sn['precision']:>10.4f} {sn['recall']:>10.4f} {sn['f1_score']:>10.4f}")
    
    return comparison


def main():
    parser = argparse.ArgumentParser(
        description="LLM vs SonarQube SAST Comparison Engine"
    )
    parser.add_argument(
        "--output", "-o",
        default="./reports",
        help="Output directory for reports (default: ./reports)"
    )
    parser.add_argument(
        "--dataset",
        default="simulated",
        choices=["simulated"],
        help="Dataset to use (default: simulated)"
    )
    
    args = parser.parse_args()
    
    # Run comparison
    result = run_full_comparison(output_dir=args.output)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
