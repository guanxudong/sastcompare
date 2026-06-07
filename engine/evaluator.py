"""
Evaluator: Compare LLM and SonarQube detection results.
Computes precision, recall, F1, false positive/negative rates, and cost metrics.
"""
import json
import logging
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, asdict, field
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class DetectionMetrics:
    """Binary classification metrics for vulnerability detection."""
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    
    @property
    def precision(self) -> float:
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)
    
    @property
    def recall(self) -> float:
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)
    
    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        if p + r == 0:
            return 0.0
        return 2 * p * r / (p + r)
    
    @property
    def false_positive_rate(self) -> float:
        if self.false_positives + self.true_negatives == 0:
            return 0.0
        return self.false_positives / (self.false_positives + self.true_negatives)
    
    @property
    def false_negative_rate(self) -> float:
        if self.false_negatives + self.true_positives == 0:
            return 0.0
        return self.false_negatives / (self.false_negatives + self.true_positives)
    
    @property
    def accuracy(self) -> float:
        total = self.true_positives + self.true_negatives + self.false_positives + self.false_negatives
        if total == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / total
    
    def to_dict(self) -> Dict:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
            "accuracy": round(self.accuracy, 4)
        }


@dataclass
class CostMetrics:
    """Cost analysis metrics."""
    total_tokens_input: int = 0
    total_tokens_output: int = 0
    total_cost_usd: float = 0.0
    avg_cost_per_sample: float = 0.0
    cost_per_vulnerability_found: float = 0.0
    analysis_duration_ms: int = 0
    avg_duration_ms: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            "total_tokens_input": self.total_tokens_input,
            "total_tokens_output": self.total_tokens_output,
            "total_cost_usd": round(self.total_cost_usd, 6),
            "avg_cost_per_sample": round(self.avg_cost_per_sample, 6),
            "cost_per_vulnerability_found": round(self.cost_per_vulnerability_found, 6) if self.cost_per_vulnerability_found != float('inf') else None,
            "analysis_duration_ms": self.analysis_duration_ms,
            "avg_duration_ms": round(self.avg_duration_ms, 2)
        }


@dataclass
class ComparisonResult:
    """Complete comparison between LLM and SonarQube."""
    scanner_name: str  # "SonarQube" or LLM model name
    scanner_type: str  # "rule_based" or "llm"
    
    # Overall metrics
    overall_metrics: DetectionMetrics = field(default_factory=DetectionMetrics)
    
    # Per-language metrics
    language_metrics: Dict[str, DetectionMetrics] = field(default_factory=dict)
    
    # Per-CWE metrics
    cwe_metrics: Dict[str, DetectionMetrics] = field(default_factory=dict)
    
    # Per-vulnerability-type metrics
    vuln_type_metrics: Dict[str, DetectionMetrics] = field(default_factory=dict)
    
    # Cost metrics (for LLM only)
    cost_metrics: Optional[CostMetrics] = None
    
    # Coverage stats
    total_samples: int = 0
    vulnerable_samples: int = 0
    safe_samples: int = 0
    vulnerabilities_detected: int = 0
    
    def to_dict(self) -> Dict:
        result = {
            "scanner_name": self.scanner_name,
            "scanner_type": self.scanner_type,
            "overall_metrics": self.overall_metrics.to_dict(),
            "language_metrics": {k: v.to_dict() for k, v in self.language_metrics.items()},
            "cwe_metrics": {k: v.to_dict() for k, v in self.cwe_metrics.items()},
            "vuln_type_metrics": {k: v.to_dict() for k, v in self.vuln_type_metrics.items()},
            "total_samples": self.total_samples,
            "vulnerable_samples": self.vulnerable_samples,
            "safe_samples": self.safe_samples,
            "vulnerabilities_detected": self.vulnerabilities_detected
        }
        if self.cost_metrics:
            result["cost_metrics"] = self.cost_metrics.to_dict()
        return result


class Evaluator:
    """Evaluates and compares detection results."""
    
    def __init__(self, ground_truth: List[Dict]):
        """Initialize with ground truth data.
        
        Args:
            ground_truth: List of sample dicts with 'sample_id', 'is_vulnerable', 'language', 'cwe_id', 'vuln_type'
        """
        self.ground_truth = {s["sample_id"]: s for s in ground_truth}
        self.samples = ground_truth
    
    def evaluate_sonarqube(self, sonar_results: List[Dict]) -> ComparisonResult:
        """Evaluate SonarQube detection results."""
        result = ComparisonResult(
            scanner_name="SonarQube Enterprise",
            scanner_type="rule_based"
        )
        
        # Build lookup by sample_id
        sonar_by_id = {r["sample_id"]: r for r in sonar_results}
        
        # Initialize per-category metrics
        lang_metrics = defaultdict(DetectionMetrics)
        cwe_metrics = defaultdict(DetectionMetrics)
        vuln_metrics = defaultdict(DetectionMetrics)
        overall = DetectionMetrics()
        
        vulnerabilities_found = 0
        
        for sample in self.samples:
            sid = sample["sample_id"]
            gt_vulnerable = sample["is_vulnerable"]
            
            sonar_result = sonar_by_id.get(sid, {})
            detected = sonar_result.get("detected", False)
            
            if gt_vulnerable and detected:
                overall.true_positives += 1
                lang_metrics[sample["language"]].true_positives += 1
                cwe_metrics[sample["cwe_id"]].true_positives += 1
                vuln_metrics[sample["vuln_type"]].true_positives += 1
                vulnerabilities_found += 1
            elif not gt_vulnerable and detected:
                overall.false_positives += 1
                lang_metrics[sample["language"]].false_positives += 1
                cwe_metrics[sample["cwe_id"]].false_positives += 1
                vuln_metrics[sample["vuln_type"]].false_positives += 1
            elif not gt_vulnerable and not detected:
                overall.true_negatives += 1
                lang_metrics[sample["language"]].true_negatives += 1
                cwe_metrics[sample["cwe_id"]].true_negatives += 1
                vuln_metrics[sample["vuln_type"]].true_negatives += 1
            else:  # gt_vulnerable and not detected
                overall.false_negatives += 1
                lang_metrics[sample["language"]].false_negatives += 1
                cwe_metrics[sample["cwe_id"]].false_negatives += 1
                vuln_metrics[sample["vuln_type"]].false_negatives += 1
        
        result.overall_metrics = overall
        result.language_metrics = dict(lang_metrics)
        result.cwe_metrics = dict(cwe_metrics)
        result.vuln_type_metrics = dict(vuln_metrics)
        result.total_samples = len(self.samples)
        result.vulnerable_samples = sum(1 for s in self.samples if s["is_vulnerable"])
        result.safe_samples = result.total_samples - result.vulnerable_samples
        result.vulnerabilities_detected = vulnerabilities_found
        
        return result
    
    def evaluate_llm(self, llm_results: List[Dict], model_name: str) -> ComparisonResult:
        """Evaluate LLM detection results."""
        result = ComparisonResult(
            scanner_name=model_name,
            scanner_type="llm"
        )
        
        llm_by_id = {r["sample_id"]: r for r in llm_results}
        
        lang_metrics = defaultdict(DetectionMetrics)
        cwe_metrics = defaultdict(DetectionMetrics)
        vuln_metrics = defaultdict(DetectionMetrics)
        overall = DetectionMetrics()
        
        cost = CostMetrics()
        vulnerabilities_found = 0
        
        for sample in self.samples:
            sid = sample["sample_id"]
            gt_vulnerable = sample["is_vulnerable"]
            
            llm_result = llm_by_id.get(sid, {})
            detected = llm_result.get("vulnerabilities_found", False)
            
            # Update cost metrics
            if "tokens_input" in llm_result:
                cost.total_tokens_input += llm_result["tokens_input"]
            if "tokens_output" in llm_result:
                cost.total_tokens_output += llm_result["tokens_output"]
            if "cost_usd" in llm_result:
                cost.total_cost_usd += llm_result["cost_usd"]
            if "analysis_duration_ms" in llm_result:
                cost.analysis_duration_ms += llm_result["analysis_duration_ms"]
            
            if gt_vulnerable and detected:
                overall.true_positives += 1
                lang_metrics[sample["language"]].true_positives += 1
                cwe_metrics[sample["cwe_id"]].true_positives += 1
                vuln_metrics[sample["vuln_type"]].true_positives += 1
                vulnerabilities_found += 1
            elif not gt_vulnerable and detected:
                overall.false_positives += 1
                lang_metrics[sample["language"]].false_positives += 1
                cwe_metrics[sample["cwe_id"]].false_positives += 1
                vuln_metrics[sample["vuln_type"]].false_positives += 1
            elif not gt_vulnerable and not detected:
                overall.true_negatives += 1
                lang_metrics[sample["language"]].true_negatives += 1
                cwe_metrics[sample["cwe_id"]].true_negatives += 1
                vuln_metrics[sample["vuln_type"]].true_negatives += 1
            else:
                overall.false_negatives += 1
                lang_metrics[sample["language"]].false_negatives += 1
                cwe_metrics[sample["cwe_id"]].false_negatives += 1
                vuln_metrics[sample["vuln_type"]].false_negatives += 1
        
        # Calculate cost averages
        if result.total_samples > 0:
            cost.avg_cost_per_sample = cost.total_cost_usd / result.total_samples
            cost.avg_duration_ms = cost.analysis_duration_ms / result.total_samples
        if vulnerabilities_found > 0:
            cost.cost_per_vulnerability_found = cost.total_cost_usd / vulnerabilities_found
        else:
            cost.cost_per_vulnerability_found = float('inf')
        
        result.overall_metrics = overall
        result.language_metrics = dict(lang_metrics)
        result.cwe_metrics = dict(cwe_metrics)
        result.vuln_type_metrics = dict(vuln_metrics)
        result.cost_metrics = cost
        result.total_samples = len(self.samples)
        result.vulnerable_samples = sum(1 for s in self.samples if s["is_vulnerable"])
        result.safe_samples = result.total_samples - result.vulnerable_samples
        result.vulnerabilities_detected = vulnerabilities_found
        
        return result
    
    def compare_all(self, sonar_results: List[Dict], 
                   llm_opus_results: List[Dict],
                   llm_sonnet_results: List[Dict]) -> Dict[str, Any]:
        """Run full comparison across all scanners."""
        sonar_eval = self.evaluate_sonarqube(sonar_results)
        opus_eval = self.evaluate_llm(llm_opus_results, "Claude Opus 4.1")
        sonnet_eval = self.evaluate_llm(llm_sonnet_results, "Claude Sonnet 4")
        
        return {
            "sonarqube": sonar_eval.to_dict(),
            "claude_opus": opus_eval.to_dict(),
            "claude_sonnet": sonnet_eval.to_dict(),
            "summary": self._generate_summary(sonar_eval, opus_eval, sonnet_eval)
        }
    
    def _generate_summary(self, sonar: ComparisonResult, 
                         opus: ComparisonResult,
                         sonnet: ComparisonResult) -> Dict:
        """Generate executive summary of comparison."""
        return {
            "best_f1": max([
                ("SonarQube", sonar.overall_metrics.f1_score),
                ("Claude Opus 4.1", opus.overall_metrics.f1_score),
                ("Claude Sonnet 4", sonnet.overall_metrics.f1_score)
            ], key=lambda x: x[1]),
            "best_recall": max([
                ("SonarQube", sonar.overall_metrics.recall),
                ("Claude Opus 4.1", opus.overall_metrics.recall),
                ("Claude Sonnet 4", sonnet.overall_metrics.recall)
            ], key=lambda x: x[1]),
            "best_precision": max([
                ("SonarQube", sonar.overall_metrics.precision),
                ("Claude Opus 4.1", opus.overall_metrics.precision),
                ("Claude Sonnet 4", sonnet.overall_metrics.precision)
            ], key=lambda x: x[1]),
            "cost_efficiency": [
                {
                    "scanner": "Claude Opus 4.1",
                    "total_cost": opus.cost_metrics.total_cost_usd if opus.cost_metrics else 0,
                    "cost_per_vuln": opus.cost_metrics.cost_per_vulnerability_found if opus.cost_metrics else 0
                },
                {
                    "scanner": "Claude Sonnet 4",
                    "total_cost": sonnet.cost_metrics.total_cost_usd if sonnet.cost_metrics else 0,
                    "cost_per_vuln": sonnet.cost_metrics.cost_per_vulnerability_found if sonnet.cost_metrics else 0
                }
            ],
            "vulnerability_coverage": {
                "sonarqube": sonnet.vulnerabilities_detected,
                "claude_opus": opus.vulnerabilities_detected,
                "claude_sonnet": sonnet.vulnerabilities_detected,
                "total_vulnerabilities": sonar.vulnerable_samples
            }
        }


def generate_comparison_report(comparison: Dict, output_path: str = "./reports/comparison_report.json"):
    """Save comparison results to JSON report."""
    import os
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(comparison, f, indent=2)
    
    logger.info(f"Comparison report saved to {output_path}")


if __name__ == "__main__":
    # Test
    gt = [
        {"sample_id": "JAVA-SQLI-001", "is_vulnerable": True, "language": "Java", "cwe_id": "CWE-89", "vuln_type": "SQL Injection"},
        {"sample_id": "JAVA-SAFE-001", "is_vulnerable": False, "language": "Java", "cwe_id": "CWE-89", "vuln_type": "SQL Injection"}
    ]
    
    sonar = [{"sample_id": "JAVA-SQLI-001", "detected": True}]
    llm = [{"sample_id": "JAVA-SQLI-001", "vulnerabilities_found": True, "tokens_input": 2000, "tokens_output": 500, "cost_usd": 0.006, "analysis_duration_ms": 500}]
    
    eval = Evaluator(gt)
    result = eval.compare_all(sonar, llm, llm)
    print(json.dumps(result, indent=2))
