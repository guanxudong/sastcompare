# LLM-Powered Security Audit for Large Codebases

A practical workflow to audit medium-to-large repositories with LLMs when the full repo exceeds context limits.

---

## 1. The Problem

- **SAST tools** (Semgrep, SonarQube) catch rule-based bugs (SQLi, XSS, hardcoded keys).
- **LLMs** catch logic flaws (IDOR, auth bypass, race conditions, state-machine bugs) that rules miss.
- **But**: an entire repo is too large for an LLM context window.

> Goal: Feed the LLM **only the code that matters** — the attack surface and the paths that lead to dangerous operations.

---

## 2. Three-Tool Pipeline

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│ Semgrep  │────→│CodeGraph │────→│   LLM    │
│(Find Sinks)│    │(Find Path)│    │(Find Logic│
│            │    │            │    │  Bugs)   │
└──────────┘     └──────────┘     └──────────┘
```

| Tool | Role | Why it matters |
|------|------|----------------|
| **Semgrep** | Scans the whole repo and tags every *dangerous function* (Sink). | You get a precise list of files/lines where sensitive operations happen. |
| **CodeGraph** | Traces *which entry points* can reach each Sink. | Replaces `grep`. It sees cross-file call chains **and** dynamic edges (callbacks, middleware, event buses). |
| **LLM** | Analyzes the complete *story* from user input to sensitive operation. | Finds permission bypasses, business-logic flaws, and architectural trust issues that rules cannot see. |

---

## 3. Step-by-Step Workflow

### Step 0 — Raw Repo (Too Big)

```
[Repo: 500 files]
   ├── tests/          (150 files)
   ├── frontend/       (100 files)
   ├── config/docs/    (80 files)
   ├── utils/dto/      (50 files)
   └── business logic/ (120 files)  ← only these matter
```

**Problem**: Feeding all 500 files wastes tokens and buries the real attack surface.

---

### Step 1 — Coarse Filtering (Remove Noise)

Delete what can never contain a business-logic vulnerability:
- Test files (`*test*`, `*spec*`)
- Static assets (CSS, HTML, images)
- Third-party dependencies (`node_modules/`, `vendor/`)
- CI/CD configs, docs, Dockerfiles (unless you audit deployment)
- Pure DTOs/utility helpers with no auth or state logic

**Result**: `~500 files → ~200 files`

---

### Step 2 — Find Entry Points (CodeGraph)

CodeGraph auto-detects routes for **17 web frameworks** (Express, FastAPI, Django, Spring, Gin, etc.).

**Query**:
```bash
codegraph explore "show all API entry points and route handlers"
```

**What you get**:
```
Entry: POST /api/users/:id/update
  └─ File: src/router.py:42
  └─ Handler: user_update_handler()

Entry: GET /api/admin/export
  └─ File: src/admin.py:15
  └─ Handler: admin_export()
```

**Result**: `~200 files → ~50-80 files` (only user-reachable code).

---

### Step 3 — Find Sinks (Semgrep)

Run Semgrep in **taint mode** to locate every dangerous function. You do not care whether the finding is a true vulnerability here; you only want the *location*.

```bash
semgrep --config=auto --json . > sinks.json
```

**Example Sink list**:
```json
[
  {"path": "src/models/user.py", "line": 45, "sink": "db.raw_query"},
  {"path": "src/utils/helper.js", "line": 22, "sink": "child_process.exec"},
  {"path": "src/api/admin.go", "line": 88, "sink": "os.WriteFile"}
]
```

**Result**: A precise map of every sensitive operation in the repo.

---

### Step 4 — Build Chains (CodeGraph Replaces Grep)

For **each Sink**, ask CodeGraph to trace the path from entry to Sink.

```bash
codegraph explore "trace path from entry points to db.raw_query in src/models/user.py"
```

**What CodeGraph returns** (what `grep` cannot do):
```
Chain: POST /api/users/:id/update
  ├─ [Entry] router.py:42     user_update_handler(req)
  ├─ [Auth]  middleware.py:8  require_login(req)
  ├─ [Logic] controller.py:20 validate_and_update(user_id, payload)
  └─ [Sink]  models.py:45      db.raw_query(sql)
```

**Key advantage**: CodeGraph follows **dynamic edges** (middleware chains, event emitters, interface implementations) that `grep`/`ripgrep` miss entirely.

**Result**: `~50-80 files → ~20-40 files` organized into complete chains.

---

### Step 5 — Slice & Group (Fit Context Window)

**Within each chain file**, keep only the functions that participate in the vulnerability story:

| Keep | Drop |
|------|------|
| Entry function (parameter parsing) | Pure utilities (`formatDate`, `logger.debug`) |
| Auth/permission checks | Full DTO definitions (keep only field names) |
| Business logic (state transitions, calculations) | Config readers (one line is enough) |
| Sink function + its call context | Constants, enums, error-code lists |

**Group by business module** (do not feed everything at once):

```
Batch 1: Authentication & Authorization
Batch 2: User & Resource Management (IDOR risk)
Batch 3: Core Business Logic (orders, payments, state machines)
Batch 4: Admin & Bulk Operations
Batch 5: External Integrations (webhooks, SSRF risk)
```

**Target**: Each batch stays within **30K–80K tokens**.

---

### Step 6 — Prompt the LLM (Find What Rules Miss)

For each batch, send a **single chain story** with this prompt structure:

```markdown
## Chain Overview
Entry: POST /api/users/:id/update
Sink: db.raw_query() at src/models/user.py:45
Files involved: router.py, middleware.py, controller.py, models.py

## Entry Code
[Full handler source with parameter parsing]

## Auth / Validation Logic
[Permission checks, input validation]

## Business Logic
[State transitions, calculations, condition branches]

## Sink Code
[The sensitive operation and its immediate context]

## Task
Semgrep and SonarQube already covered basic injection flaws.
Find what they **miss**:
1. IDOR / privilege escalation
2. Business-logic bypasses (skipping steps, race conditions)
3. Architecture flaws (internal APIs exposed, missing audit logs)
4. Concrete reproduction steps
```

**Why this works**: The LLM sees the *complete story* — from user input through permission checks to the sensitive operation — so it can spot logic gaps that pattern matchers cannot.

---

## 4. Why Not Just Grep?

| Task | `grep` / `ripgrep` | CodeGraph |
|------|-------------------|-----------|
| Find string occurrences | ✅ Fast | Unnecessary (Semgrep does this) |
| Find framework routes | ❌ Regex guessing | ✅ Auto-detects 17 frameworks |
| Find "who calls X" | ❌ Only static imports | ✅ Cross-file + dynamic edges |
| Find "path from A to B" | ❌ Impossible | ✅ Returns full call chain |

**Conclusion**: Once Semgrep marks the Sinks, CodeGraph replaces grep entirely for path discovery.

---

## 5. Summary Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    FULL REPO (500 files)                    │
│  tests/  frontend/  docs/  config/  vendor/  logic/       │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 1: Coarse Filter                                       │
│  Remove tests, assets, docs, vendor                         │
│  Result: ~200 files                                         │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 2: Find Entry Points (CodeGraph)                       │
│  "show all API routes"                                      │
│  Result: ~50-80 user-reachable files                        │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 3: Find Sinks (Semgrep)                                │
│  "where are db.query, exec, eval, WriteFile?"               │
│  Result: JSON list of (file, line, sink)                      │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 4: Build Chains (CodeGraph)                            │
│  "trace path from entry to each sink"                       │
│  Result: complete call chains (Entry → Auth → Logic → Sink)│
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 5: Slice & Group by Module                             │
│  Keep only story-relevant functions; drop utilities/DTOs    │
│  Result: 5-8 batches, 30K-80K tokens each                 │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 6: LLM Analysis (per batch)                            │
│  "Find what Semgrep/SonarQube missed"                       │
│  Result: logic bugs, auth bypasses, IDOR, race conditions  │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. Key Takeaways

1. **Semgrep** gives you the *targets* (Sinks).
2. **CodeGraph** gives you the *paths* (Entry → Sink chains), replacing grep entirely.
3. **Slicing** keeps only the functions that tell the security story.
4. **Grouping by module** keeps each LLM prompt within context limits and focused.
5. **Prompt explicitly** for what rules miss — logic flaws, not syntax bugs.
