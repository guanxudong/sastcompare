"""
Configuration for the LLM vs SonarQube SAST Comparison Engine.
"""
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class SonarQubeConfig:
    """SonarQube server configuration."""
    host_url: str = os.getenv("SONAR_HOST_URL", "http://localhost:9000")
    token: str = os.getenv("SONAR_TOKEN", "")
    project_key: str = os.getenv("SONAR_PROJECT_KEY", "llm-comparison-poc")
    
    @property
    def auth_header(self) -> Dict[str, str]:
        import base64
        credentials = base64.b64encode(f"{self.token}:".encode()).decode()
        return {"Authorization": f"Basic {credentials}"}


@dataclass
class LLMConfig:
    """LLM API configuration."""
    anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    model_opus: str = "claude-opus-4-1-20250819"
    model_sonnet: str = "claude-sonnet-4-20250514"
    model_haiku: str = "claude-haiku-4-20250514"
    max_tokens: int = 4096
    temperature: float = 0.1
    
    # Pricing per 1M tokens (input/output) - as of 2026
    pricing: Dict[str, Dict[str, float]] = field(default_factory=lambda: {
        "claude-opus-4-1-20250819": {"input": 5.00, "output": 25.00, "cached": 0.50},
        "claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00, "cached": 0.30},
        "claude-haiku-4-20250514": {"input": 1.00, "output": 5.00, "cached": 0.10},
    })


@dataclass
class DatasetConfig:
    """Vulnerability dataset configuration."""
    base_path: str = "./datasets"
    
    # Dataset URLs and identifiers
    sources: Dict[str, Dict] = field(default_factory=lambda: {
        "owasp_benchmark": {
            "name": "OWASP Benchmark",
            "url": "https://github.com/OWASP/Benchmark",
            "languages": ["Java"],
            "test_cases": 21041,
            "description": "Java test suite for SAST accuracy evaluation"
        },
        "juliet_java": {
            "name": "Juliet Test Suite (Java)",
            "url": "https://samate.nist.gov/SARD/test-suites/109",
            "languages": ["Java"],
            "test_cases": 28881,
            "description": "NIST SARD Java test cases covering 112 CWEs"
        },
        "juliet_cpp": {
            "name": "Juliet Test Suite (C/C++)", 
            "url": "https://samate.nist.gov/SARD/test-suites/116",
            "languages": ["C", "C++"],
            "test_cases": 64099,
            "description": "NIST SARD C/C++ test cases covering 112 CWEs"
        },
        "securityeval": {
            "name": "SecurityEval",
            "url": "https://github.com/VulnExpo/SecurityEval",
            "languages": ["Python"],
            "test_cases": 130,
            "description": "Python vulnerability samples for LLM evaluation"
        },
    })


@dataclass
class EvaluationConfig:
    """Evaluation and scoring configuration."""
    # Metrics to compute
    metrics: List[str] = field(default_factory=lambda: [
        "precision", "recall", "f1_score", "false_positive_rate", 
        "false_negative_rate", "true_positive_rate"
    ])
    
    # CWE categories to evaluate
    cwe_categories: List[str] = field(default_factory=lambda: [
        "CWE-79", "CWE-89", "CWE-22", "CWE-78", "CWE-94",
        "CWE-862", "CWE-863", "CWE-20", "CWE-200", "CWE-502"
    ])
    
    # Vulnerability types
    vuln_types: List[str] = field(default_factory=lambda: [
        "SQL Injection", "XSS", "Path Traversal", "Command Injection",
        "Code Injection", "Insecure Deserialization", "Hardcoded Secrets",
        "Insecure Direct Object Reference", "Security Misconfiguration"
    ])


# Global config instances
sonar_config = SonarQubeConfig()
llm_config = LLMConfig()
dataset_config = DatasetConfig()
eval_config = EvaluationConfig()
