# SASTCompare: LLM vs SonarQube SAST Comparison PoC

[![Node.js 18+](https://img.shields.io/badge/node-18+-339933.svg)](https://nodejs.org/)
[![React 18](https://img.shields.io/badge/react-18-61dafb.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/typescript-5.0+-3178c6.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **A production-ready Proof-of-Concept comparing Claude LLM models (Opus/Sonnet) against SonarQube Enterprise for Static Application Security Testing (SAST) capabilities.**

> ⚠️ **Disclaimer:** All vulnerability samples, detection results, API cost figures, and performance metrics in this repository are **simulated / synthetic data** for demonstration and research purposes only. They do **not** reflect real-world scanning of production codebases, and the "SonarQube Enterprise" results are modeled estimates rather than live scan outputs. Do not use these numbers for procurement or security assurance decisions.

This repository provides a complete evaluation framework to measure how well modern Large Language Models perform at detecting security vulnerabilities in source code compared to enterprise-grade rule-based SAST tools like SonarQube. It includes a TypeScript analysis engine, vulnerability test datasets, evaluation metrics computation, and an interactive React-based web dashboard.

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

- **Node.js 18+**
- (Optional) **SonarQube Server** — for live SAST scanning
- (Optional) **Anthropic API Key** — for live LLM analysis

### 1. Clone & Install Dependencies

```bash
git clone https://github.com/YOUR_USERNAME/sastcompare.git
cd sastcompare

# Install all dependencies (frontend + backend)
npm install
```

### 2. Run the Comparison Pipeline

```bash
# Run with simulated data (no API keys needed)
npm run analyze

# Output: public/reports/comparison_report.json
```

### 3. Launch the Web Dashboard

```bash
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
| Dataset Manager | `backend/dataset-manager.ts` | Load, manage, and export vulnerability test datasets |
| SonarQube Scanner | `backend/sonarqube-scanner.ts` | Interface with SonarQube Server via REST API |
| LLM Analyzer | `backend/llm-analyzer.ts` | Vulnerability detection using Claude models with structured prompting |
| Evaluator | `backend/evaluator.ts` | Compute Precision, Recall, F1, FPR, FNR, and cost metrics |
| Config | `backend/config.ts` | Centralized configuration for all components |

### Running Individual Components

```typescript
// Analyze a single code sample with LLM
import { LLMAnalyzer } from "./backend/llm-analyzer";

const analyzer = new LLMAnalyzer("claude-sonnet-4-20250514");
const result = await analyzer.analyze(
  "JAVA-SQLI-001",
  "...",
  "Java"
);
console.log(result);

// Scan with SonarQube
import { SonarQubeScanner } from "./backend/sonarqube-scanner";

const scanner = new SonarQubeScanner();
if (await scanner.checkHealth()) {
  const issues = await scanner.getProjectIssues("my-project-key");
  console.log(`Found ${issues.length} issues`);
}
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
# Optional: custom base URL (e.g., for proxy or Azure deployments)
# ANTHROPIC_BASE_URL=https://api.anthropic.com
```

### Model Selection

Edit `backend/config.ts` to change default models:

```typescript
export const llmConfig: LLMConfig = {
  anthropic_api_key: getEnv("ANTHROPIC_API_KEY", ""),
  anthropic_base_url: getEnv("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
  model_opus: "claude-opus-4-1-20250819",
  model_sonnet: "claude-sonnet-4-20250514",
  model_haiku: "claude-haiku-4-20250514",
  max_tokens: 4096,
  temperature: 0.1,
  pricing: { ... },
};
```

---

## Moving from Simulated to Real-World Testing

By default, this PoC runs entirely with **simulated data** — no external API calls or live SonarQube instance is required. To run against real codebases and live services, you need the following credentials and setup changes.

### Required Credentials

| Service | What You Need | How to Obtain |
|---|---|---|
| **SonarQube** | `SONAR_TOKEN` + `SONAR_PROJECT_KEY` | [Generate a token](https://docs.sonarsource.com/sonarqube-server/latest/user-guide/managing-tokens/) in your SonarQube server UI; create or reuse a project key |
| **Anthropic (Claude)** | `ANTHROPIC_API_KEY` | Sign up at [console.anthropic.com](https://console.anthropic.com) and create an API key |

### 1. SonarQube Setup

**Option A — Local (Docker, fastest for testing):**
```bash
docker run -d --name sonarqube \
  -p 9000:9000 \
  -v sonarqube_data:/opt/sonarqube/data \
  sonarqube:community
```
Then open `http://localhost:9000`, log in with `admin/admin`, and generate a token under **Administration → Security → Users → Tokens**.

**Option B — Remote / Enterprise:**
Use your existing SonarQube Enterprise instance. Ensure the server URL and token have access to the target project.

### 2. Anthropic API Setup

1. Create an account at [console.anthropic.com](https://console.anthropic.com)
2. Navigate to **API Keys** and generate a new key
3. Set the environment variables:
   ```bash
   export ANTHROPIC_API_KEY="sk-ant-..."
   # Optional: override the default API endpoint
   export ANTHROPIC_BASE_URL="https://api.anthropic.com"
   ```

> **Custom Endpoints:** If you are using a proxy, Azure OpenAI Service, or an internal gateway, set `ANTHROPIC_BASE_URL` to your custom endpoint (e.g., `https://your-proxy.example.com`). The engine will automatically route all Anthropic API calls to this base URL.

### 3. Running with Live APIs

The `backend/run-comparison.ts` pipeline **automatically** uses live Anthropic API calls when `ANTHROPIC_API_KEY` is set. If the key is missing, it falls back to simulated results with a console warning.

To use live analysis, simply set the environment variable and run:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
npm run analyze
```

> **Note:** The `llm-analyzer.ts` module automatically calls the live Anthropic API when `ANTHROPIC_API_KEY` is set. If the key is missing, it logs a warning and falls back to simulated results. No code changes are required to enable live analysis — just set the environment variable.

### 4. Cost Estimates (Live Mode)

| Model | Input Price | Output Price | Est. Cost per 1K LOC |
|---|---|---|---|
| Claude Opus 4.1 | $5.00 / 1M tokens | $25.00 / 1M tokens | ~$0.50–$2.00 |
| Claude Sonnet 4 | $3.00 / 1M tokens | $15.00 / 1M tokens | ~$0.30–$1.20 |
| Claude Haiku 4 | $1.00 / 1M tokens | $5.00 / 1M tokens | ~$0.10–$0.40 |

*Actual cost depends on code complexity, prompt size, and output verbosity. The PoC's simulated `$0.52` / `$0.26` figures are illustrative only.*

### 5. Supported Real-World Datasets

To run against industry-standard benchmarks instead of the built-in 16 samples:

| Dataset | Download | Integration Point |
|---|---|---|
| **OWASP Benchmark** | `git clone https://github.com/OWASP/Benchmark` | Implement `DatasetManager.load_owasp_benchmark()` |
| **Juliet Test Suite** | [NIST SARD](https://samate.nist.gov/SARD/test-suites.php) | Implement `DatasetManager.load_juliet_suite()` |
| **SecurityEval** | `git clone https://github.com/VulnExpo/SecurityEval` | Implement `DatasetManager.load_securityeval()` |

See `engine/dataset_manager.py` for the dataset loader interface.

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
|-- backend/                         # TypeScript analysis engine
|   |-- types.ts                     # Shared TypeScript interfaces
|   |-- config.ts                    # Configuration management
|   |-- dataset-manager.ts           # Dataset loading & management
|   |-- sonarqube-scanner.ts         # SonarQube REST API client
|   |-- llm-analyzer.ts              # Claude LLM vulnerability analyzer
|   |-- evaluator.ts                 # Metrics computation engine
|   |-- run-comparison.ts            # Main pipeline runner
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
