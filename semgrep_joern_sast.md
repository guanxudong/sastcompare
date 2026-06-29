# Intelligent SAST Audit Pipeline: Semgrep + Joern + PydanticAI

## Technical Specification v1.0

---

## 1. Overview

This document specifies an enterprise-grade, orchestrated automated security audit pipeline. It combines **Semgrep** for broad pattern matching, **Joern** for deep cross-procedural data-flow verification, and **PydanticAI** as the agent orchestration framework to deliver fully automated analysis from source code repository to structured security report.

### 1.1 Objectives
- **Automation**: End-to-end unattended execution from code ingestion to report generation
- **Precision**: Three-layer funnel (Semgrep triage -> Joern data-flow validation -> LLM semantic confirmation) to minimize false positives
- **Orchestration**: PydanticAI Agent Framework enabling task decomposition, parallel execution, and state persistence
- **Actionability**: Deliver a consolidated report ranked by severity, including vulnerability location, impact analysis, and concise remediation guidance

### 1.2 Technology Stack
| Component | Role | Minimum Version |
|-----------|------|-----------------|
| **Semgrep** | Static pattern matching; rapid Sink candidate discovery | >= 1.70 |
| **Joern** | CPG graph analysis; cross-procedural data-flow verification | >= 2.0 |
| **PydanticAI** | Agent orchestration framework; type-safe workflow definition | >= 0.8 |
| **LLM** | Semantic analysis, PoC generation, remediation recommendations | GPT-4o / Claude 3.5 |

---

## 2. Architecture

```
+---------------------------------------------------------------------+
|                         Orchestrator (PydanticAI)                    |
|  +--------------+  +--------------+  +--------------+  +---------+ |
|  |  Stage 1     |  |  Stage 2     |  |  Stage 3     |  | Stage 4 | |
|  |  CPG Build   |->|  Semgrep     |->|  Joern       |->| LLM     | |
|  |  (Serial)    |  |  (Parallel)  |  |  (Parallel)  |  |(Parallel| |
|  +--------------+  +--------------+  +--------------+  +---------+ |
|         |                    |                |              |      |
|    +----------------------------------------------------------+   |
|    |  Stage 5: Final Report Generation (Serial Aggregation)   |   |
|    |  - Deduplicate, Sort, CVSS Scoring                       |   |
|    |  - Generate Unified Security Report                     |   |
|    +----------------------------------------------------------+   |
+---------------------------------------------------------------------+
```

---

## 3. Five-Stage Workflow

### Stage 1: Project Preprocessing & CPG Build (Serial, Non-Parallelizable)

**Goal**: Prepare foundational artifacts for all downstream analysis.

**Tasks**:
1. Clone or update the target code repository
2. Resolve dependencies (detect language, framework, and build system)
3. Build Joern CPG: `joern-parse ./src --output app.cpg.bin`
4. Export symbol index (method names, class names, file tree) for fast lookup
5. Initialize PydanticAI global state

**Why Serial**:
- The CPG is the sole data source for all subsequent Joern queries
- The file-tree index enables Semgrep to skip unchanged files efficiently
- Global state (project metadata, language type) must be finalized before any Agent starts

**Outputs**:
- `app.cpg.bin` — Joern graph database
- `project_meta.json` — language, framework, entry files
- `symbol_index.json` — method name to file path mapping

---

### Stage 2: Semgrep Breadth Scanning (Parallelizable, by Rule Set)

**Goal**: Rapidly cover the entire codebase and produce candidate vulnerability points.

**Tasks**:
1. Load multiple rule sets and scan in parallel:
   - `p/owasp-top-ten` — general vulnerabilities
   - `p/sql-injection` — SQL injection specific
   - `p/command-injection` — command injection specific
   - `p/xss` — cross-site scripting specific
   - `p/security-audit` — audit mode
2. Standardize output into the internal `VulnerabilityCandidate` model
3. Preliminary deduplication: merge duplicate hits on the same file and line

**Parallel Strategy**:
```python
import asyncio
from pydantic_ai import Agent

semgrep_rules = [
    "p/owasp-top-ten",
    "p/sql-injection",
    "p/command-injection",
    "p/xss",
    "p/security-audit"
]

async def run_semgrep_agent(rule: str) -> list[VulnerabilityCandidate]:
    agent = Agent(
        'openai:gpt-4o',
        tools=[run_semgrep_scan],
        result_type=list[VulnerabilityCandidate]
    )
    return await agent.run(f"Scan with rule {rule}")

# Parallel execution
results = await asyncio.gather(*[
    run_semgrep_agent(rule) for rule in semgrep_rules
])
```

**Why Parallelizable**:
- Each rule set scans independently with no shared mutable state
- Semgrep processes are read-only against source code, producing no resource conflicts
- Results are naturally mergeable (JSON array concatenation)

**Outputs**:
- `semgrep_candidates.json` — candidate vulnerability list (file, line, rule ID, confidence)

---

### Stage 3: Joern Deep Data-Flow Verification (Parallelizable, by Sink Batch)

**Goal**: Verify whether Semgrep candidate Sinks are actually reachable by external (tainted) input.

**Tasks**:
1. Extract Sink method names and locations from Semgrep results
2. Build the Source set (HTTP entry points, message-queue consumers, file-upload handlers, etc.)
3. Execute `reachableByFlows` query for each Sink:
   ```scala
   // Joern CPGQL query template
   def source = cpg.method.name(".*(doGet|doPost|handleRequest|process).*").parameter
   def sink = cpg.call.name("executeQuery").argument
   sink.reachableByFlows(source).p
   ```
4. For confirmed data-flow paths, execute **Program Slicing** to extract taint-relevant code
5. Serialize slice results into the `TaintPath` model

**Parallel Strategy**:
```python
from pydantic import BaseModel
from pydantic_ai import Agent, RunContext

class TaintPath(BaseModel):
    source_method: str
    sink_method: str
    flow_depth: int
    slice_code: str
    file_chain: list[str]
    line_chain: list[int]

class JoernValidationDeps:
    cpg_path: str
    project_dir: str

async def validate_sink_batch(
    ctx: RunContext[JoernValidationDeps],
    sink_batch: list[str]
) -> list[TaintPath]:
    agent = Agent(
        'openai:gpt-4o',
        deps_type=JoernValidationDeps,
        tools=[joern_query_reachable_flows, joern_program_slice],
        result_type=list[TaintPath]
    )
    return await agent.run(
        f"Validate data flows for sinks: {sink_batch}",
        deps=ctx.deps
    )

# Parallel by batches (5-10 sinks per batch to avoid Joern memory bloat)
sink_batches = [sinks[i:i+5] for i in range(0, len(sinks), 5)]
taint_paths = await asyncio.gather(*[
    validate_sink_batch(ctx, batch) for batch in sink_batches
])
```

**Why Parallelizable**:
- Joern supports multiple independent CPG queries (read-only graph traversal)
- Each Sink data-flow verification has no state dependency on others
- Limit batch size (recommend <= 10 Sinks) to avoid Joern memory explosion

**Serial Constraints**:
- Must wait for Stage 2 completion (requires Semgrep Sink list as input)
- Must wait for Stage 1 completion (requires CPG already built)

**Outputs**:
- `taint_paths.json` — confirmed taint paths with slice code, call chain, and line mappings

---

### Stage 4: LLM Semantic Analysis & PoC Generation (Parallelizable, by Path Batch)

**Goal**: Perform semantic judgment on Joern-verified taint paths, producing vulnerability confirmation, PoC, and remediation guidance.

**Tasks**:
1. Load `TaintPath` data
2. Construct a structured Prompt (call chain + slice code + audit tasks)
3. Invoke LLM for:
   - Vulnerability confirmation (Vulnerable / Not Vulnerable)
   - Vulnerability type classification (SQLi / CMDi / XSS / etc.)
   - CVSS scoring and risk level assignment
   - Exploit condition analysis
   - PoC payload generation
   - Fix code suggestions
4. Write results into the `VulnerabilityReport` model

**PydanticAI Agent Design**:
```python
from pydantic import BaseModel, Field
from typing import Literal

class VulnerabilityReport(BaseModel):
    vuln_id: str = Field(description="Unique ID, e.g., VULN-2026-001")
    title: str = Field(description="Vulnerability title, e.g., SQL Injection in UserController")
    severity: Literal["Critical", "High", "Medium", "Low", "Info"]
    cvss_score: float = Field(ge=0.0, le=10.0)
    
    location: str = Field(description="Vulnerability location, e.g., src/controller/UserController.java:15")
    sink_location: str = Field(description="Sink location, e.g., src/dao/UserDAO.java:42")
    
    description: str = Field(description="What the vulnerability is and how it forms")
    impact: str = Field(description="How it affects the application and potential consequences")
    exploit_condition: str = Field(description="Conditions required to exploit, e.g., no authentication needed")
    poc_payload: str = Field(description="PoC payload")
    fix_suggestion: str = Field(description="Concise remediation with code example")
    
    confidence: Literal["high", "medium", "low"]
    taint_path: str = Field(description="Taint path as a human-readable string")
    data_flow_verified: bool = Field(description="Whether Joern data-flow verification passed")

class LLMAnalysisDeps:
    model_name: str = "gpt-4o"
    max_tokens: int = 4096

vuln_analysis_agent = Agent(
    'openai:gpt-4o',
    deps_type=LLMAnalysisDeps,
    result_type=VulnerabilityReport,
    system_prompt=(
        "You are a senior application-security auditor. Based on the provided taint path and code slice, "
        "determine whether a real vulnerability exists and produce a structured analysis report. "
        "Analysis principles: "
        "1. If effective sanitization is present (parameterized queries, strict whitelist), mark as NOT VULNERABLE. "
        "2. If vulnerable, provide a specific CVSS score and exploitable conditions. "
        "3. Remediation suggestions must include directly usable code snippets. "
        "4. Use English for all descriptive fields."
    )
)

async def analyze_taint_path(
    ctx: RunContext[LLMAnalysisDeps],
    path: TaintPath
) -> VulnerabilityReport:
    prompt = build_analysis_prompt(path)
    return await vuln_analysis_agent.run(prompt, deps=ctx.deps)

# Parallel analysis (5-10 paths per batch to respect LLM RPM limits)
semaphore = asyncio.Semaphore(10)
async def analyze_with_limit(path: TaintPath):
    async with semaphore:
        return await analyze_taint_path(ctx, path)

analysis_tasks = [analyze_with_limit(path) for path in all_taint_paths]
reports = await asyncio.gather(*analysis_tasks, return_exceptions=True)
```

**Why Parallelizable**:
- Each taint-path analysis is completely independent
- LLM API calls are naturally parallel (subject to RPM/TPM limits)
- Results are naturally aggregatable into a list

**Serial Constraints**:
- Must wait for Stage 3 completion (requires Joern-verified `TaintPath`)

**Outputs**:
- `raw_reports.json` — raw vulnerability report list (may contain duplicates)

---

### Stage 5: Final Report Generation (Serial, Non-Parallelizable)

**Goal**: Aggregate, deduplicate, sort, and emit the final consolidated security report.

**Tasks**:
1. **Load all reports**: Read from Stage 4 `raw_reports.json`
2. **Deduplicate**: Merge duplicate reports for the same Sink (keep the longest / most dangerous path)
3. **Filter**: Drop entries with `confidence == "low"` or `data_flow_verified == false`
4. **Sort**: By `severity` (Critical > High > Medium > Low) -> `cvss_score` (desc) -> `confidence` (high to low)
5. **Generate unified report** (Markdown + JSON dual format)

**Why Serial**:
- Deduplication requires a global view (cross-batch comparison of Sink locations)
- Sorting requires the full dataset
- Report numbering (VULN-001) needs a global increment
- Statistical summary (total count, severity distribution) requires full aggregation

**PydanticAI Aggregation Agent**:
```python
from pydantic_ai import Agent
from datetime import datetime

class FinalReport(BaseModel):
    project_name: str
    scan_time: str
    total_files: int
    total_vulns: int
    severity_distribution: dict[str, int]
    vulnerabilities: list[VulnerabilityReport]
    executive_summary: str

report_agent = Agent(
    'openai:gpt-4o',
    result_type=FinalReport,
    system_prompt=(
        "You are a security-reporting expert. Aggregate raw vulnerability reports into a professional audit report. "
        "Requirements: "
        "1. Sort by severity from highest to lowest. "
        "2. Merge duplicate reports for the same Sink. "
        "3. Generate an executive summary for management. "
        "4. Use English for all output."
    )
)

async def generate_final_report(
    raw_reports: list[VulnerabilityReport],
    project_meta: dict
) -> FinalReport:
    # Local deduplication and sorting (structured ops, no LLM needed)
    deduped = deduplicate_by_sink(raw_reports)
    sorted_reports = sorted(
        deduped,
        key=lambda r: (severity_order(r.severity), -r.cvss_score, -confidence_order(r.confidence))
    )
    
    # Assign IDs
    for i, report in enumerate(sorted_reports, 1):
        report.vuln_id = f"VULN-{datetime.now().year}-{i:03d}"
    
    # Generate executive summary via LLM
    severity_dist = count_by_severity(sorted_reports)
    summary_prompt = (
        f"Generate a management summary based on the following vulnerability data: "
        f"Project: {project_meta['name']}, Total files: {project_meta['total_files']}, "
        f"Total vulnerabilities: {len(sorted_reports)}, "
        f"Critical: {sum(1 for r in sorted_reports if r.severity == 'Critical')}, "
        f"High: {sum(1 for r in sorted_reports if r.severity == 'High')}, "
        f"Medium: {sum(1 for r in sorted_reports if r.severity == 'Medium')}, "
        f"Low: {sum(1 for r in sorted_reports if r.severity == 'Low')}. "
        f"Generate an English summary within 200 words describing overall risk posture and top priority fixes."
    )
    
    summary = await report_agent.run(summary_prompt)
    
    return FinalReport(
        project_name=project_meta['name'],
        scan_time=datetime.now().isoformat(),
        total_files=project_meta['total_files'],
        total_vulns=len(sorted_reports),
        severity_distribution=severity_dist,
        vulnerabilities=sorted_reports,
        executive_summary=summary.data.executive_summary
    )
```

**Outputs**:
- `security_report.md` — human-readable, sorted by severity
- `security_report.json` — machine-readable, for CI/CD consumption

---

## 4. Final Report Format

### 4.1 Markdown Report Example

```markdown
# Security Audit Report

**Project**: user-service  
**Scan Time**: 2026-06-29 14:30:00  
**Total Files**: 1,247  
**Total Vulnerabilities**: 12  

## Executive Summary
This audit discovered 12 valid vulnerabilities, including 3 Critical and 5 High severity issues. The most severe risks are concentrated in SQL injection within the user authentication module and command execution in the admin console. Immediate remediation is recommended.

---

## Critical (3)

### VULN-2026-001: SQL Injection in UserController.login
- **Location**: `src/controller/UserController.java:15` -> `src/dao/UserDAO.java:42`
- **What it is**: The `username` parameter flows directly from the HTTP request into SQL string concatenation without prepared statements or parameterization.
- **Impact**: Attackers can bypass authentication without credentials using `admin OR 1=1`, and potentially read the entire database.
- **Exploit Condition**: No authentication required; any user can trigger.
- **Fix**: Replace string concatenation with `PreparedStatement`:
  ```java
  // Before (Vulnerable)
  String sql = "SELECT * FROM users WHERE name = '" + username + "'";
  stmt.executeQuery(sql);
  
  // After (Safe)
  String sql = "SELECT * FROM users WHERE name = ?";
  PreparedStatement ps = conn.prepareStatement(sql);
  ps.setString(1, username);
  ps.executeQuery();
  ```
- **CVSS**: 9.8 | **Confidence**: High | **Data Flow Verified**: Yes

### VULN-2026-002: Command Injection in ReportGenerator.runTask
...

---

## High (5)

### VULN-2026-004: XSS via Unescaped User Input in CommentServlet
...

---

## Medium (3)
...

## Low (1)
...
```

### 4.2 JSON Report Structure
```json
{
  "project_name": "user-service",
  "scan_time": "2026-06-29T14:30:00",
  "total_files": 1247,
  "total_vulns": 12,
  "severity_distribution": {
    "Critical": 3,
    "High": 5,
    "Medium": 3,
    "Low": 1
  },
  "executive_summary": "This audit discovered 12 valid vulnerabilities...",
  "vulnerabilities": [
    {
      "vuln_id": "VULN-2026-001",
      "title": "SQL Injection in UserController.login",
      "severity": "Critical",
      "cvss_score": 9.8,
      "location": "src/controller/UserController.java:15",
      "sink_location": "src/dao/UserDAO.java:42",
      "description": "username parameter flows from HTTP request directly into SQL concatenation...",
      "impact": "Attackers can bypass authentication and read entire database...",
      "exploit_condition": "No authentication required; any user can trigger",
      "poc_payload": "admin OR 1=1",
      "fix_suggestion": "Use PreparedStatement to replace string concatenation...",
      "confidence": "high",
      "taint_path": "UserController.handleRequest -> UserService.login -> UserDAO.findByUsername -> executeQuery",
      "data_flow_verified": true
    }
  ]
}
```

---

## 5. Complete PydanticAI Workflow Code

```python
#!/usr/bin/env python3
# semgrep_joern_pydanticai_pipeline.py
# Complete pipeline implementation

import asyncio
import json
import os
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext
from pydantic_ai.models.openai import OpenAIModel


# ============ Data Models ============

class VulnerabilityCandidate(BaseModel):
    rule_id: str
    file_path: str
    line_number: int
    method_name: str
    severity_hint: str
    code_snippet: str

class TaintPath(BaseModel):
    source_method: str
    sink_method: str
    flow_depth: int
    slice_code: str
    file_chain: list[str]
    line_chain: list[int]
    data_flow_confirmed: bool

class VulnerabilityReport(BaseModel):
    vuln_id: str = ""
    title: str
    severity: Literal["Critical", "High", "Medium", "Low", "Info"]
    cvss_score: float = Field(ge=0.0, le=10.0)
    location: str
    sink_location: str
    description: str
    impact: str
    exploit_condition: str
    poc_payload: str
    fix_suggestion: str
    confidence: Literal["high", "medium", "low"]
    taint_path: str
    data_flow_verified: bool

class FinalReport(BaseModel):
    project_name: str
    scan_time: str
    total_files: int
    total_vulns: int
    severity_distribution: dict[str, int]
    vulnerabilities: list[VulnerabilityReport]
    executive_summary: str


# ============ Tool Functions (Mock) ============

async def run_semgrep_scan(rule: str) -> list[VulnerabilityCandidate]:
    # Execute Semgrep scan (actual implementation calls subprocess)
    return []

async def joern_query_reachable_flows(
    ctx: RunContext,
    sink_methods: list[str]
) -> list[TaintPath]:
    # Execute Joern data flow query (actual implementation calls joern-cli)
    return []

async def joern_program_slice(
    ctx: RunContext,
    method_name: str,
    variable: str
) -> str:
    # Execute Joern program slicing
    return ""


# ============ Agent Definitions ============

# Stage 2: Semgrep Scan Agent
semgrep_agent = Agent(
    model='openai:gpt-4o',
    result_type=list[VulnerabilityCandidate],
    tools=[run_semgrep_scan],
    system_prompt="Execute Semgrep scan and standardize output"
)

# Stage 3: Joern Validation Agent
joern_agent = Agent(
    model='openai:gpt-4o',
    result_type=list[TaintPath],
    tools=[joern_query_reachable_flows, joern_program_slice],
    system_prompt="Execute Joern data flow validation and program slicing"
)

# Stage 4: LLM Analysis Agent
llm_agent = Agent(
    model='openai:gpt-4o',
    result_type=VulnerabilityReport,
    system_prompt=(
        "Perform semantic analysis based on taint path, determine vulnerability validity and generate report. "
        "Output must strictly conform to VulnerabilityReport structure."
    )
)

# Stage 5: Report Aggregation Agent
report_agent = Agent(
    model='openai:gpt-4o',
    result_type=FinalReport,
    system_prompt=(
        "Aggregate vulnerability reports, deduplicate, sort, and generate management summary"
    )
)


# ============ Main Pipeline ============

async def main_pipeline(project_dir: str, project_name: str):
    # Main pipeline orchestration
    
    # ===== Stage 1: Serial - CPG Build =====
    print("[Stage 1] Building CPG...")
    total_files = sum(1 for _ in os.walk(project_dir) for f in _[2] if f.endswith('.java'))
    
    # ===== Stage 2: Parallel - Semgrep Scan =====
    print("[Stage 2] Parallel Semgrep scanning...")
    rules = ["p/owasp-top-ten", "p/sql-injection", "p/command-injection", "p/xss"]
    semgrep_tasks = [semgrep_agent.run(f"Scan {project_dir} with {rule}") for rule in rules]
    semgrep_results = await asyncio.gather(*semgrep_tasks)
    all_candidates = [c for sublist in semgrep_results for c in sublist.data]
    print(f"  Discovered {len(all_candidates)} candidates")
    
    # ===== Stage 3: Parallel - Joern Validation =====
    print("[Stage 3] Parallel Joern data flow validation...")
    sink_batches = [all_candidates[i:i+5] for i in range(0, len(all_candidates), 5)]
    joern_tasks = [
        joern_agent.run(f"Validate sinks: {[c.method_name for c in batch]}")
        for batch in sink_batches
    ]
    joern_results = await asyncio.gather(*joern_tasks)
    all_taint_paths = [p for sublist in joern_results for p in sublist.data if p.data_flow_confirmed]
    print(f"  Confirmed {len(all_taint_paths)} valid taint paths")
    
    # ===== Stage 4: Parallel - LLM Analysis =====
    print("[Stage 4] Parallel LLM semantic analysis...")
    semaphore = asyncio.Semaphore(10)
    async def analyze_with_limit(path: TaintPath):
        async with semaphore:
            return await llm_agent.run(f"Analyze taint path: {path.model_dump_json()}")
    
    llm_tasks = [analyze_with_limit(path) for path in all_taint_paths]
    llm_results = await asyncio.gather(*llm_tasks)
    raw_reports = [r.data for r in llm_results]
    print(f"  Generated {len(raw_reports)} raw reports")
    
    # ===== Stage 5: Serial - Final Report =====
    print("[Stage 5] Generating final report...")
    
    # Local deduplication and sorting (structured operations)
    deduped = deduplicate_reports(raw_reports)
    sorted_reports = sorted(
        deduped,
        key=lambda r: (
            {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}[r.severity],
            -r.cvss_score,
            {"high": 0, "medium": 1, "low": 2}[r.confidence]
        )
    )
    
    # Assign IDs
    for i, report in enumerate(sorted_reports, 1):
        report.vuln_id = f"VULN-{datetime.now().year}-{i:03d}"
    
    # Generate executive summary
    severity_dist = count_by_severity(sorted_reports)
    summary_input = (
        f"Project: {project_name}, Total vulns: {len(sorted_reports)}, "
        f"Critical: {severity_dist.get('Critical', 0)}, "
        f"High: {severity_dist.get('High', 0)}, "
        f"Medium: {severity_dist.get('Medium', 0)}, "
        f"Low: {severity_dist.get('Low', 0)}"
    )
    summary_result = await report_agent.run(f"Generate summary for: {summary_input}")
    
    final_report = FinalReport(
        project_name=project_name,
        scan_time=datetime.now().isoformat(),
        total_files=total_files,
        total_vulns=len(sorted_reports),
        severity_distribution=severity_dist,
        vulnerabilities=sorted_reports,
        executive_summary=summary_result.data.executive_summary
    )
    
    # Output report
    with open("security_report.json", "w", encoding="utf-8") as f:
        json.dump(final_report.model_dump(), f, ensure_ascii=False, indent=2)
    
    print("[Done] Report saved to security_report.json")
    return final_report


# ============ Helper Functions ============

def deduplicate_reports(reports: list[VulnerabilityReport]) -> list[VulnerabilityReport]:
    # Deduplicate by sink location, keeping highest CVSS
    seen = {}
    for r in reports:
        key = r.sink_location
        if key not in seen or r.cvss_score > seen[key].cvss_score:
            seen[key] = r
    return list(seen.values())

def count_by_severity(reports: list[VulnerabilityReport]) -> dict[str, int]:
    dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for r in reports:
        dist[r.severity] = dist.get(r.severity, 0) + 1
    return dist


if __name__ == "__main__":
    asyncio.run(main_pipeline("./src", "user-service"))
```

---

## 6. Parallelization Strategy Summary

| Stage | Parallelism | Split Dimension | Concurrency Limit | Depends On |
|-------|-------------|----------------|-------------------|------------|
| **Stage 1** CPG Build | Serial | None | 1 | None |
| **Stage 2** Semgrep Scan | Parallel | By rule set | Unlimited | Stage 1 |
| **Stage 3** Joern Validation | Parallel | By sink batch | Memory bound | Stage 2 |
| **Stage 4** LLM Analysis | Parallel | By path batch | RPM/TPM bound | Stage 3 |
| **Stage 5** Final Report | Serial | None | 1 | Stage 4 |

### 6.1 Why Stage 1 and Stage 5 Must Be Serial?
- **Stage 1**: The CPG is the physical foundation for all subsequent queries; the file-tree index is needed for Semgrep to skip unchanged files efficiently
- **Stage 5**: Deduplication requires a global view (cross-batch comparison of Sink locations); sorting requires the full dataset; report numbering requires a global increment; statistical summary requires full aggregation

### 6.2 Why Stage 2/3/4 Can Be Parallel?
- **No shared mutable state**: Each task only reads source code / CPG and writes no shared data
- **Results are mergeable**: JSON arrays naturally support append and concatenation
- **Failure isolation**: A single batch failure does not affect other batches (with `return_exceptions=True`)

---

## 7. Deployment & Execution

### 7.1 Environment Requirements
```bash
# Install Semgrep
pip install semgrep

# Install Joern (download prebuilt package)
wget https://github.com/joernio/joern/releases/download/v2.0.0/joern-cli.zip
unzip joern-cli.zip && export PATH=$PATH:$(pwd)/joern-cli/bin

# Install Python dependencies
pip install pydantic-ai openai
```

### 7.2 Run Command
```bash
export OPENAI_API_KEY="sk-..."
python3 semgrep_joern_pydanticai_pipeline.py
```

### 7.3 CI/CD Integration
```yaml
# .github/workflows/security-audit.yml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Pipeline
        run: |
          pip install pydantic-ai semgrep
          # Joern uses prebuilt cache
          python3 semgrep_joern_pydanticai_pipeline.py
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security_report.json
```

---

## 8. Limitations & Upgrade Path

| Limitation | Current Solution | Upgrade Path |
|------------|-----------------|--------------|
| Joern build is slow | Serial build | Incremental build (only changed files) |
| LLM cost is high | Full analysis | Use cheap model for initial screening, then GPT-4 for refinement |
| No interactive confirmation | Fully automated | Add manual review node (Stage 4.5) |
| Single project scan | Single process | Multi-project parallel (each project independent pipeline) |

---

*Document Version: 1.0*  
*Last Updated: 2026-06-29*
