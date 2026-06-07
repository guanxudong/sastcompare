# AGENTS.md — AI Agent Collaboration Guide

> This file provides context for AI agents (GitHub Copilot, Cursor, Claude, etc.) working on this codebase. Read this before making any changes.

---

## Project Purpose

This is a **Proof-of-Concept (PoC)** comparing Claude LLM models against SonarQube Enterprise for Static Application Security Testing (SAST). The goal is to evaluate whether LLMs can effectively detect code vulnerabilities and whether a mid-tier model (Sonnet) with a well-designed agent harness can approach the performance of a top-tier model (Opus).

**Key business question:** Can we build a self-developed LLM-based product to replace or augment SonarQube for our organization's code security scanning needs?

---

## Architecture at a Glance

### Two-Layer System

1. **TypeScript Analysis Engine** (`backend/`) — The backend that runs security scans
2. **React Web Dashboard** (`src/`) — The frontend that visualizes results

### Data Flow

```
Vulnerability Datasets (16 simulated samples)
       |
       +---> SonarQube Scanner (rule-based) ---> Detection Results
       +---> LLM Analyzer (Claude Opus/Sonnet) ---> Detection Results + Cost
       |
       +---> Evaluator (Precision/Recall/F1/Cost) ---> Comparison Report (JSON)
       |
       +---> React Web UI (Charts/Tables/Visualizations)
```

---

## Code Organization

### TypeScript Backend (`backend/`)

| File | Responsibility | Key Exports |
|---|---|---|
| `types.ts` | Shared TypeScript interfaces (backend + frontend) | `DetectionMetrics`, `CostMetrics`, `ComparisonResult`, `LLMAnalysisResult`, etc. |
| `config.ts` | All configuration (SonarQube, LLM, datasets, evaluation) | `sonarConfig`, `llmConfig`, `datasetConfig`, `evalConfig` |
| `dataset-manager.ts` | Load/export vulnerability test samples | `DatasetManager` |
| `sonarqube-scanner.ts` | SonarQube REST API + simulated SAST detection | `SonarQubeScanner`, `runSonarQubeAnalysis` |
| `llm-analyzer.ts` | Claude LLM vulnerability analysis with structured prompts | `LLMAnalyzer`, `runLLMAnalysis` |
| `evaluator.ts` | Binary classification metrics + cost analysis | `Evaluator`, `generateComparisonReport` |
| `run-comparison.ts` | Main orchestrator — runs the full pipeline | CLI entry point |

### React Frontend (`src/`)

| Component | Displays |
|---|---|
| `MetricsOverview.tsx` | Scanner metric cards (Precision/Recall/F1/Detected/Cost) |
| `ComparisonCharts.tsx` | Radar chart, bar charts, pie charts, cost charts (uses Recharts) |
| `DetailedTable.tsx` | Full metrics comparison table with "Best" badges |
| `PerLanguageAnalysis.tsx` | Per-language and per-vuln-type breakdowns |
| `ResearchContext.tsx` | Research background, Mythos context, cost analysis, insights |
| `App.tsx` | Main layout with tabs, hero section, footer |

### Data Flow (Frontend)

```
backend/run-comparison.ts  (generates report)
       |
public/reports/comparison_report.json
       |
src/data/reportData.ts  (TypeScript types + JSON loader)
       |
All React components import from reportData.ts
```

---

## Critical Design Decisions

### 1. Simulated vs. Live Detection

**Current state:** Both SonarQube and LLM detection results are **simulated** based on published research findings. This allows the PoC to demonstrate the framework without requiring live API access.

**Simulated data is in:**
- `sonarqube-scanner.ts` → `SIMULATED_RESULTS` dict
- `llm-analyzer.ts` → `SIMULATED_RESULTS` dict (per model)

**To switch to live detection:**
- Set `ANTHROPIC_API_KEY` env var for Claude API calls
- Optionally set `ANTHROPIC_BASE_URL` for custom endpoints (proxy, Azure, etc.)
- Set `SONAR_TOKEN` and `SONAR_HOST_URL` for SonarQube
- The `LLMAnalyzer.analyze()` method automatically calls the live Anthropic API when `ANTHROPIC_API_KEY` is present; otherwise it logs a warning and falls back to simulated results

### 2. The Prompt Engineering Approach

The LLM Analyzer uses a **single-shot system prompt** with strict JSON output format. The prompt includes:
- Identity definition ("expert security analyst")
- 15 specific vulnerability types to detect
- CWE mapping requirements
- Output JSON schema constraints
- Negative constraints ("Do NOT flag secure patterns")

**This prompt is intentionally conservative** — it prioritizes precision over recall by explicitly telling the model not to speculate.

### 3. Cost Tracking Design

Every LLM analysis result includes token counts and estimated USD cost. This is not just for reporting — it's a **first-class evaluation metric**. The evaluator compares scanners not just on accuracy but on cost-per-vulnerability-found.

### 4. Modular Evaluation

The `Evaluator` class is designed to be scanner-agnostic. It accepts any list of detection results (from SonarQube, Claude, GPT, DeepSeek, etc.) and computes the same set of metrics. Adding a new scanner requires only:
1. A new scanner module that outputs results in the standard format
2. One line in `Evaluator.compare_all()`

---

## Common Modification Patterns

### Adding a New Vulnerability Sample

1. Add sample data to `dataset-manager.ts` → `SAMPLE_VULNERABILITIES[language]`
2. Add expected SonarQube detection to `sonarqube-scanner.ts` → `SIMULATED_RESULTS`
3. Add expected LLM detection to `llm-analyzer.ts` → `SIMULATED_RESULTS` (for each model)
4. Re-run `npm run analyze`

### Adding a New LLM Model

1. Add model config to `config.ts` → `llmConfig.pricing`
2. Add token estimates to `llm-analyzer.ts` → `AVG_TOKENS_PER_SAMPLE`
3. Add simulated results to `llm-analyzer.ts` → `SIMULATED_RESULTS[new_model_id]`
4. Add model to `run-comparison.ts` analysis pipeline
5. Add model to `reportData.ts` → `scanners` array

### Changing the UI Theme/Colors

Scanner colors are defined in `src/data/reportData.ts`:
```typescript
const scanners = [
  { key: 'sonarqube', name: 'SonarQube Enterprise', color: '#4C9AFF' },  // Blue
  { key: 'claude_opus', name: 'Claude Opus 4.1', color: '#FF6B6B' },     // Red
  { key: 'claude_sonnet', name: 'Claude Sonnet 4', color: '#4ECDC4' },   // Teal
];
```

These colors propagate to all charts and UI elements. Changing them here updates the entire dashboard.

---

## Testing & Validation

### Running the Pipeline

```bash
npm run analyze
```

This should produce:
- `public/reports/comparison_report.json` — main report
- `public/reports/sonarqube_results.json` — SonarQube raw results
- `public/reports/opus_results.json` — Claude Opus raw results
- `public/reports/sonnet_results.json` — Claude Sonnet raw results

### Verifying the Dashboard

```bash
npm install
npm run build
# Check for TypeScript errors
```

### Expected Console Output

```
============================================================
LLM vs SonarQube SAST Comparison Engine
============================================================
[1/6] Loading vulnerability dataset...
  Loaded 16 samples
  Vulnerable: 12, Safe: 4
  Languages: {'Java': 8, 'C': 2, 'Python': 6}
...
Scanner               Precision     Recall         F1
----------------------------------------------------
SonarQube                1.0000     0.8333     0.9091
Claude Opus 4.1          1.0000     1.0000     1.0000
Claude Sonnet 4          1.0000     0.9167     0.9565
```

---

## Technology Stack

### Backend
- Node.js 18+
- TypeScript 5.0+
- `axios` (HTTP client for SonarQube & Anthropic APIs)
- `commander` (CLI argument parsing)

### Frontend
- React 18 + TypeScript + Vite
- Tailwind CSS 3.4
- shadcn/ui (pre-installed component library)
- Recharts (charts)
- Lucide React (icons)

### Tooling
- TypeScript strict mode
- Vite for build/dev
- `tsx` for running TypeScript scripts
- PostCSS + Autoprefixer

---

## File Naming Conventions

- **TypeScript/React:** `PascalCase.tsx` for components, `camelCase.ts` for utilities
- **Backend TypeScript:** `kebab-case.ts` for modules, `PascalCase` for classes
- **JSON data:** `snake_case.json`
- **CSS:** Uses Tailwind utility classes; minimal custom CSS in `App.css`

---

## Known Limitations (Agent Should Be Aware)

1. **Simulated results** — Not real API calls. The detection behavior is approximated from research papers.
2. **Small dataset** — 16 samples is tiny. Real benchmarks have 20K+ samples.
3. **Async/await** — The backend uses async/await for API calls and file I/O.
4. **No caching** — Every re-run re-computes everything. Production should cache LLM responses.
5. **No SARIF output** — SonarQube produces SARIF; LLM outputs JSON. A SARIF converter would be needed for CI/CD integration.
6. **TypeScript `as unknown as`** — The JSON import in `reportData.ts` uses this cast because the JSON structure doesn't perfectly match the tuple types. This is intentional for the PoC.

---

## Glossary

| Term | Meaning |
|---|---|
| **SAST** | Static Application Security Testing — analyzing source code for vulnerabilities without executing it |
| **CWE** | Common Weakness Enumeration — standardized taxonomy of software weaknesses |
| **TP/FP/FN/TN** | True Positive / False Positive / False Negative / True Negative |
| **F1 Score** | Harmonic mean of Precision and Recall; the primary comparison metric |
| **Harness** | The system/prompt/agent architecture that wraps around the LLM to produce structured results |
| **Mythos** | Anthropic's unreleased security-specialized model (higher capability than Opus) |
| **SCA** | Software Composition Analysis — detecting vulnerabilities in third-party dependencies |
