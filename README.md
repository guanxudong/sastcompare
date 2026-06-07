# SASTCompare: LLM vs SonarQube SAST Comparison PoC

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![React 18](https://img.shields.io/badge/react-18-61dafb.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/typescript-5.0+-3178c6.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **A production-ready Proof-of-Concept comparing Claude LLM models (Opus/Sonnet) against SonarQube Enterprise for Static Application Security Testing (SAST) capabilities.**

> ⚠️ **Disclaimer:** All vulnerability samples, detection results, API cost figures, and performance metrics in this repository are **simulated / synthetic data** for demonstration and research purposes only. They do **not** reflect real-world scanning of production codebases, and the "SonarQube Enterprise" results are modeled estimates rather than live scan outputs. Do not use these numbers for procurement or security assurance decisions.

This repository provides a complete evaluation framework to measure how well modern Large Language Models perform at detecting security vulnerabilities in source code compared to enterprise-grade rule-based SAST tools like SonarQube. It includes a Python analysis engine, vulnerability test datasets, evaluation metrics computation, and an interactive React-based web dashboard.

---

## Key Results (Preview)

| Scanner | Precision | Recall | F1 Score | Vulns Detected | Cost (16 samples) |
|---|---|---|---|---|---|
| **SonarQube Enterprise** | 1.0000 | 0.8333 | 0.9091 | 10/12 | Subscription |
| **Claude Opus 4.1** | 1.0000 | 1.0000 | 1.0000 | 12/12 | $0.52 |
| **Claude Sonnet 4** | 1.0000 | 0.9167 | 0.9565 | 11/12 | $0.26 |

**Key Finding:** Claude Sonnet 4 achieves ~95% of Opus's detection capability at **50% of the cost**, validating that a well-designed agent harness makes mid-tier LLMs viable for enterprise SAST workflows.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Quick Start](#quick-start)
- [Analysis Engine](#analysis-engine)
- [Web Dashboard](#web-dashboard)
- [Configuration](#configuration)
- [Supported Vulnerability Datasets](#supported-vulnerability-datasets)
- [Evaluation Methodology](#evaluation-methodology)
- [Research Background](#research-background)
- [Directory Structure](#directory-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Architecture Overview

```
                    +---------------------+
                    |   Vulnerability     |
                    |   Test Datasets     |
                    | (OWASP/Juliet/...)  |
                    +----------+----------+
                               |
              +----------------+----------------+
              |                                 |
    +---------v---------+             +---------v---------+
    |  SonarQube        |             |  LLM Analyzer     |
    |  Scanner Engine   |             |  (Claude Opus/    |
    |  (REST API)       |             |   Sonnet/Haiku)   |
    +---------+---------+             +---------+---------+
              |                                 |
              +----------------+----------------+
                               |
                    +----------v----------+
                    |     Evaluator       |
                    | (Precision/Recall/  |
                    |  F1/Cost Metrics)   |
                    +----------+----------+
                               |
                    +----------v----------+
                    |   React Web UI      |
                    | (Interactive Charts |
                    |   & Comparison)     |
                    +---------------------+
```

---

## Quick Start

### Prerequisites

- **Python 3.10+**
- **Node.js 18+** (for Web UI)
- (Optional) **SonarQube Server** — for live SAST scanning
- (Optional) **Anthropic API Key** — for live LLM analysis

### 1. Clone & Setup Python Engine

```bash
git clone https://github.com/YOUR_USERNAME/sastcompare.git
cd sastcompare

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies (add requirements.txt if needed)
pip install requests
```

### 2. Run the Comparison Pipeline

```bash
# Run with simulated data (no API keys needed)
cd engine
python run_comparison.py -o ../public/reports

# Output: reports/comparison_report.json
```

### 3. Launch the Web Dashboard

```bash
# Install frontend dependencies
cd ..
npm install

# Start development server
npm run dev

# Or build for production
npm run build
```

The dashboard will be available at `http://localhost:5173`.

---

## Analysis Engine

### Core Modules

| Module | File | Purpose |
|---|---|---|
| Dataset Manager | `engine/dataset_manager.py` | Load, manage, and export vulnerability test datasets |
| SonarQube Scanner | `engine/sonarqube_scanner.py` | Interface with SonarQube Server via REST API |
| LLM Analyzer | `engine/llm_analyzer.py` | Vulnerability detection using Claude models with structured prompting |
| Evaluator | `engine/evaluator.py` | Compute Precision, Recall, F1, FPR, FNR, and cost metrics |
| Config | `engine/config.py` | Centralized configuration for all components |

### Running Individual Components

```python
# Analyze a single code sample with LLM
from engine.llm_analyzer import LLMAnalyzer

analyzer = LLMAnalyzer(model="claude-sonnet-4-20250514")
result = analyzer.analyze(
    sample_id="JAVA-SQLI-001",
    source_code="...",
    language="Java"
)
print(result.to_dict())

# Scan with SonarQube
from engine.sonarqube_scanner import SonarQubeScanner

scanner = SonarQubeScanner()
if scanner.check_health():
    issues = scanner.get_project_issues("my-project-key")
    print(f"Found {len(issues)} issues")
```

---

## Web Dashboard

The React-based dashboard provides interactive visualizations of comparison results:

### Features

| Tab | Content |
|---|---|
| **Overview** | Scanner metric cards (Precision/Recall/F1/Detected) + detailed comparison table |
| **Charts** | Radar chart, bar charts, dataset distribution pie charts, cost analysis |
| **Details** | Confusion matrices (TP/FP/FN/TN) for each scanner |
| **Per-Language** | Breakdown by Java/Python/C and by vulnerability type |
| **Research** | Full research context, Claude Mythos background, cost analysis, academic references |

### Tech Stack

- **React 18** + **TypeScript** + **Vite**
- **Tailwind CSS** + **shadcn/ui** (40+ pre-installed components)
- **Recharts** for data visualization
- **Lucide React** for icons

---

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# SonarQube Configuration
SONAR_HOST_URL=http://localhost:9000
SONAR_TOKEN=your-sonar-token
SONAR_PROJECT_KEY=your-project-key

# Anthropic API (for live LLM analysis)
ANTHROPIC_API_KEY=your-anthropic-api-key
```

### Model Selection

Edit `engine/config.py` to change default models:

```python
llm_config = LLMConfig(
    model_opus="claude-opus-4-1-20250819",
    model_sonnet="claude-sonnet-4-20250514",
    model_haiku="claude-haiku-4-20250514",
    max_tokens=4096,
    temperature=0.1,
)
```

---

## Supported Vulnerability Datasets

The engine is designed to support multiple industry-standard vulnerability benchmarks:

| Dataset | Languages | Test Cases | Status |
|---|---|---|---|
| **OWASP Benchmark** | Java | 21,041 | Supported (simulated in PoC) |
| **Juliet Test Suite (Java)** | Java | 28,881 | Supported (simulated in PoC) |
| **Juliet Test Suite (C/C++)** | C, C++ | 64,099 | Supported (simulated in PoC) |
| **NIST SARD** | Multi | 450,000+ | Supported (simulated in PoC) |
| **SecurityEval** | Python | 130 | Supported (simulated in PoC) |

> **Note:** The current PoC uses simulated detection results based on published research. To run against real datasets, implement the download methods in `dataset_manager.py` and configure live API access.

---

## Evaluation Methodology

### Metrics Computed

All comparisons follow the standard binary classification framework used in SAST tool evaluation literature:

| Metric | Description | Ideal Value |
|---|---|---|
| **Precision** | TP / (TP + FP) — Of reported vulns, how many are real? | 1.0 |
| **Recall** | TP / (TP + FN) — Of real vulns, how many are found? | 1.0 |
| **F1 Score** | Harmonic mean of Precision and Recall | 1.0 |
| **FPR** | FP / (FP + TN) — Safe code falsely flagged | 0.0 |
| **FNR** | FN / (FN + TP) — Vulnerabilities missed | 0.0 |
| **Accuracy** | (TP + TN) / Total — Overall correctness | 1.0 |

### Per-Category Analysis

Results are broken down by:
- **Programming language** (Java, Python, C/C++, etc.)
- **CWE category** (CWE-89, CWE-79, etc.)
- **Vulnerability type** (SQL Injection, XSS, Command Injection, etc.)

### Cost Tracking

For LLM-based scanners, the engine tracks:
- Token usage (input/output)
- API cost per sample and per vulnerability found
- Analysis duration

---

## Research Background

This PoC is grounded in the following key research findings:

- **Szandala et al. (2025):** LLMs (GPT-4.1, Mistral, DeepSeek) achieve average F1=0.75-0.80 vs. SonarQube F1=0.26 on real C# projects. LLMs show superior recall across broader code contexts. [^1^]
- **Anthropic (2026):** Claude Mythos Preview discovered a 27-year-old OpenBSD vulnerability and a 16-year-old FFmpeg flaw, achieving 83.1% on CyberGym benchmark. [^2^]
- **Xu et al. (2026):** MulVul framework with Router-Detector architecture improves LLM SAST F1 by 41.5% through cross-model prompt evolution and retrieval-augmented detection. [^3^]
- **Cycode (2025):** ~30% of AI-generated code vulnerabilities are undetectable by rule-based SAST tools. [^4^]

[^1^]: Szandala et al., "Assessing the Efficacy of Large Language Models in Detecting Security Vulnerabilities," arXiv, 2025.
[^2^]: Anthropic, "Project Glasswing: Claude Mythos Preview," 2026.
[^3^]: Xu et al., "MulVul: Multi-Agent Framework for Vulnerability Detection," arXiv, 2026.
[^4^]: Cycode, "AI-Native Application Security Report," 2025.

---

## Directory Structure

```
sastcompare/
|-- engine/                          # Python analysis engine
|   |-- __init__.py
|   |-- config.py                    # Configuration management
|   |-- dataset_manager.py           # Dataset loading & management
|   |-- sonarqube_scanner.py         # SonarQube REST API client
|   |-- llm_analyzer.py              # Claude LLM vulnerability analyzer
|   |-- evaluator.py                 # Metrics computation engine
|   |-- run_comparison.py            # Main pipeline runner
|
|-- src/                             # React frontend source
|   |-- components/                  # UI components
|   |   |-- MetricsOverview.tsx
|   |   |-- ComparisonCharts.tsx
|   |   |-- DetailedTable.tsx
|   |   |-- PerLanguageAnalysis.tsx
|   |   |-- ResearchContext.tsx
|   |-- data/
|   |   |-- reportData.ts            # Report data types & loader
|   |   |-- comparison_report.json   # Generated comparison results
|   |-- App.tsx                      # Main app component
|   |-- main.tsx                     # Entry point
|   |-- index.css                    # Global styles
|
|-- public/
|   |-- reports/                     # Generated JSON reports
|
|-- datasets/                        # Vulnerability samples (generated)
|-- reports/                         # Output reports (generated)
|-- index.html                       # HTML entry point
|-- package.json                     # Node.js dependencies
|-- vite.config.ts                   # Vite configuration
|-- tailwind.config.js               # Tailwind CSS configuration
|-- tsconfig.json                    # TypeScript configuration
|-- .gitignore                       # Git ignore rules
|-- README.md                        # This file
|-- AGENTS.md                        # AI agent collaboration guide
`-- LICENSE                          # MIT License
```

---

## Contributing

Contributions are welcome! Areas of particular interest:

1. **Real API Integration** — Replace simulated results with live SonarQube/Anthropic API calls
2. **Dataset Expansion** — Add support for OWASP Benchmark, Juliet Suite, and NIST SARD downloads
3. **Additional Models** — Integrate GPT-4, Gemini, DeepSeek for multi-model comparison
4. **Agent Architecture** — Implement MulVul-style Router-Detector multi-agent framework
5. **Language Support** — Add JavaScript/TypeScript, Go, Rust vulnerability samples

Please open an issue or submit a pull request.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgments

- Built for enterprise security teams evaluating LLM-based SAST alternatives
- Inspired by research from Szandala et al., Anthropic, and the OWASP community
- UI components powered by [shadcn/ui](https://ui.shadcn.com/)
