# ShiftLeft Gateway — Design Document

**Date:** 2026-11-01
**Author:** Akhil Tripathi
**Status:** Draft v3

---

## 1. Intent & Why

Vulnerabilities are caught too late — at release time via Checkmarx scans. By then the code has been reviewed, merged, and bundled. Fixing it means rework, re-review, and re-release.

**ShiftLeft Gateway** moves security scanning to the earliest possible moment: **before code lands in git**. If the code has issues, it never reaches the repository. If it does reach the repo (via webhooks), it gets flagged on the PR immediately.

This replaces Checkmarx (licensed, slow, late-stage) with an open-source, AI-augmented pipeline that is:
- **Faster** — scans only changed files, runs in seconds
- **Earlier** — pre-push hooks catch issues before code hits remote
- **Free** — no per-seat or per-scan licensing
- **Smarter** — AI suggests fixes, not just findings
- **Deeper** — REA-powered dataflow analysis exceeds Checkmarx (source + binary + cross-boundary)
- **Private** — source code never leaves the local machine

---

## 2. Goals

- Match or exceed Checkmarx detection coverage using open-source scanners + FRIDAY engine
- Block vulnerable code at `git push` (pre-push hook)
- Provide AI-generated fix suggestions with developer review loop
- Output to PR comments, Jira tickets, and SARIF reports (CxFlow parity)
- Support any LLM provider (user's choice — Anthropic, OpenAI, Ollama, etc.)
- Pluggable scanner architecture — add/remove scanners without core changes
- **Zero source code sent to external LLMs** — only vulnerability metadata leaves the machine

## 3. Non-Goals

- Replacing IDE linting or real-time code analysis (developer's local tooling is theirs)
- Being a full SIEM or runtime security platform
- Managing cloud infrastructure security posture (CSPM)

## 4. Anti-Goals (what would make this a failure)

- Blocking developers for minutes on every push (must be fast)
- High false-positive rate that trains developers to ignore findings
- Requiring complex setup per-repo (should be a single install/config)
- Vendor lock-in to any specific LLM or scanner
- Leaking source code to external LLM providers

---

## 5. Architecture

### 5.1 High-Level: Tiered Scan Architecture

```
                          ShiftLeft Gateway
                          ═════════════════

  ┌─────────────────────────────────────────────────────────┐
  │                    TRIGGER LAYER                        │
  │                                                         │
  │   git pre-push hook          Webhook Listener           │
  │   (developer machine)        (CI/server)                │
  │         │                          │                    │
  │         ▼                          ▼                    │
  │   Changed files only         Changed files only         │
  └────────┬──────────────────────────┬─────────────────────┘
           │                          │
           ▼                          ▼
  ┌─────────────────┐    ┌──────────────────────────┐
  │  TIER 1: FAST   │    │  TIER 2: DEEP            │
  │  (pre-push)     │    │  (CI/webhook)            │
  │  ~5 seconds     │    │  ~2-5 minutes            │
  │                 │    │                           │
  │  Semgrep        │    │  Everything in Tier 1     │
  │  Gitleaks       │    │        +                  │
  │  Bandit         │    │  FRIDAY Engine           │
  │  Trivy          │    │  ├─ Taint analysis        │
  │                 │    │  ├─ Cross-module dataflow  │
  │  (all pattern-  │    │  ├─ Binary dep inspection  │
  │   based,        │    │  └─ Electron/runtime sec   │
  │   deterministic,│    │                           │
  │   zero cost)    │    │  (semantic, CPU-only,      │
  │                 │    │   deterministic, zero cost) │
  └────────┬────────┘    └─────────────┬──────────────┘
           │                           │
           └─────────┬─────────────────┘
                     ▼
  ┌──────────────────────────────────────────────────────┐
  │              RESULT AGGREGATOR                        │
  │  Normalize → Deduplicate → Severity → Fingerprint    │
  └──────────────────────┬───────────────────────────────┘
                         │
                         ▼
            ┌─── Findings exist? ───┐
            │                       │
           YES                      NO
            │                       │
            ▼                       ▼
  ┌──────────────────────┐    ┌──────────┐
  │  TIER 3: AI LAYER    │    │  PASS    │
  │  (only on findings)  │    │  Push /  │
  │                      │    │  Approve │
  │  Context Stripper    │    └──────────┘
  │       │              │
  │       ▼              │
  │  LLM (external API   │
  │   or local Ollama)   │
  │       │              │
  │       ▼              │
  │  Triage + Fix        │
  │  Suggestion          │
  │       │              │
  │  (costs $0.01-0.50   │
  │   per finding only)  │
  └──────────┬───────────┘
             │
             ▼
  ┌──────────────────────────────────────────────────────┐
  │              OUTPUT ROUTER                            │
  │                                                       │
  │  Terminal     PR Comments    Jira     SARIF    Dash   │
  │  (pre-push)   (GitHub/GL)   (tickets) (upload) (metrics)│
  └──────────────────────────────────────────────────────┘
```

### 5.2 FRIDAY Engine (Checkmarx / CodeQL Replacement)

> **FRIDAY** — named after Tony Stark's AI assistant. Built on REA's reverse engineering
> infrastructure, FRIDAY is the deep analysis engine that replaces Checkmarx's proprietary
> taint/dataflow analysis with something better: an engine that sees through source code,
> native binaries, and cross-boundary flows — all in one graph.

REA provides what no other open-source scanner has — **semantic dataflow analysis across source code and binaries through the same graph**.

```
  ┌────────────────────────────────────────────────────────┐
  │                    FRIDAY Engine                       │
  │                                                        │
  │  Source Code ──→ REA Semantic Graph ──→ Security Query  │
  │                        │                               │
  │           ┌────────────┼────────────────┐              │
  │           │            │                │              │
  │           ▼            ▼                ▼              │
  │    ┌───────────┐ ┌──────────┐  ┌──────────────┐       │
  │    │  Source    │ │  Sink    │  │  Propagation │       │
  │    │  Defs     │ │  Defs    │  │  Rules       │       │
  │    │           │ │          │  │              │       │
  │    │ HTTP.req  │ │ SQL()    │  │ assignment   │       │
  │    │ form.data │ │ exec()   │  │ return value │       │
  │    │ CLI.args  │ │ eval()   │  │ callback     │       │
  │    │ file.read │ │ file.w() │  │ promise      │       │
  │    │ env.var   │ │ net.send │  │ closure      │       │
  │    └───────────┘ │ crypto() │  │ object prop  │       │
  │                  └──────────┘  │ module export│       │
  │                                └──────────────┘       │
  │           │            │                │              │
  │           └────────────┼────────────────┘              │
  │                        ▼                               │
  │              ┌──────────────────┐                      │
  │              │  Taint Tracker   │                      │
  │              │                  │                      │
  │              │  "Does tainted   │                      │
  │              │   data reach a   │                      │
  │              │   sink without   │                      │
  │              │   sanitization?" │                      │
  │              └────────┬─────────┘                      │
  │                       │                                │
  │              Finding + Evidence                        │
  │              (provenance, confidence,                  │
  │               full dataflow path)                      │
  └────────────────────────────────────────────────────────┘
```

**What REA's existing infrastructure provides:**

| Component | REA Status | Security Use |
|-----------|-----------|--------------|
| JS/TS semantic graph | Built | Call resolution, property paths, closures, promises |
| Cross-module dataflow | Built | Track taint across import/export boundaries |
| Object reference tracking | Built | Track taint through object properties |
| Native value flow (P-code) | Built | Trace data through compiled native addons |
| Binary decompilation | Built | Inspect pre-built dependencies with no source |
| Electron IPC analysis | Built | Detect IPC channel exposure, context bridge leaks |
| Evidence provenance | Built | Rich context for AI triage (confidence, source, uncertainty) |
| Call graph extraction | Built | Map function call chains for taint propagation |
| Python .pyc inspection | Built | Bytecode-level analysis for Python targets |
| Java/.NET IL metadata | Built | Managed code inspection for JVM targets |

**What gets built on top:**

| Component | Description |
|-----------|------------|
| Source definitions | Catalog of taint entry points (HTTP params, user input, file I/O) |
| Sink definitions | Catalog of dangerous operations (SQL, exec, eval, file write) |
| Sanitizer definitions | Known safe transformations (parameterized queries, escaping) |
| Security query rules | CWE-mapped queries against the semantic graph |
| SARIF output mapper | Convert REA Evidence records to standard SARIF format |

**FRIDAY v1 language support:**

| Language | AST/Parsing | Dataflow | Taint | Source |
|----------|------------|----------|-------|--------|
| JavaScript/TypeScript | REA Babel parser | REA semantic graph | FRIDAY rules | Built on existing REA JS engine |
| Python | REA .pyc + AST parser | FRIDAY graph | FRIDAY rules | Extend REA Python inspection |
| Java | REA .class/JAR + SpotBugs AST | FRIDAY graph | FRIDAY rules | Extend REA managed code analysis |

**Unique advantage over Checkmarx:**

```
                    Checkmarx           ShiftLeft + FRIDAY
                    ─────────           ───────────────────
Source code          ✓                   ✓
   ↓ dataflow
Native addon         ✗ (blind)          ✓ (REA decompiles + traces)
   ↓ dataflow
Compiled binary      ✗ (blind)          ✓ (P-code value flow)
   ↓ dataflow
Runtime behavior     ✗                  ✓ (Frida/CDP instrumentation)

Cross-boundary       ✗ IMPOSSIBLE       ✓ Same graph, same query
taint tracking
```

### 5.3 Privacy Architecture — Context Stripping

**Rule: LLM never sees raw source code.**

```
  ┌─────────────────────────────────────────────────────────┐
  │                   LOCAL MACHINE (private)                │
  │                                                          │
  │  Source Code → Scanner → Raw Finding                     │
  │       │                      │                           │
  │       │              ┌───────▼──────────────┐            │
  │       │              │   Context Stripper    │            │
  │       │              │                       │            │
  │       │              │   Raw finding:        │            │
  │       │              │   ├─ code snippet ──→ REMOVED     │
  │       │              │   ├─ var names ────→ REMOVED      │
  │       │              │   ├─ file content ─→ REMOVED      │
  │       │              │   │                   │            │
  │       │              │   Keeps:              │            │
  │       │              │   ├─ CWE ID           │            │
  │       │              │   ├─ vuln type         │            │
  │       │              │   ├─ framework name    │            │
  │       │              │   ├─ abstract pattern  │            │
  │       │              │   ├─ file + line num   │            │
  │       │              │   └─ dataflow shape    │            │
  │       │              └───────┬──────────────┘            │
  │       │                      │                           │
  │       │              Stripped payload ────────────────────┼──→ LLM API
  │       │              (metadata only)                     │     (external)
  │       │                      │                           │
  │       │              Generic fix pattern ←───────────────┼──  LLM response
  │       │                      │                           │
  │       ▼                      ▼                           │
  │  ┌──────────────────────────────┐                        │
  │  │    Fix Applier (local)       │                        │
  │  │    Maps generic pattern      │                        │
  │  │    onto actual source code   │                        │
  │  └──────────────────────────────┘                        │
  │                                                          │
  │  NOTHING LEAVES THIS BOX EXCEPT METADATA                 │
  └─────────────────────────────────────────────────────────┘
```

**What goes to LLM vs what stays local:**

| Sent to LLM (metadata) | Never sent (stays local) |
|------------------------|--------------------------|
| CWE ID (e.g. CWE-89) | Actual source code |
| Vulnerability type ("SQL Injection") | File contents |
| File name + line number | Business logic |
| Abstract dataflow: "user input → param → sql query" | Variable values |
| Framework name (Express + pg) | API keys / secrets |
| Language name | Full function bodies |
| Available sanitizers | Repository contents |
| Generic code pattern (templatized) | Internal architecture |

**Three privacy modes (user configures):**

```yaml
ai:
  privacy_mode: strict    # strict | moderate | off

  # strict (default — enterprise safe):
  #   Only CWE ID, vuln type, framework, abstract dataflow pattern
  #   Zero code, zero variable names, zero file content
  #   Works safely with any external LLM API
  #
  # moderate:
  #   Sends 3-5 line anonymized snippet (variable names replaced)
  #   Better fix accuracy, small privacy trade-off
  #
  # off (self-hosted Ollama ONLY):
  #   Sends full context including code
  #   Gateway ENFORCES: if provider != ollama → blocks the request
  #   Nothing leaves the internal network
```

**Audit trail — every LLM call logged:**

```json
{
  "timestamp": "2026-11-01T10:23:45Z",
  "finding_id": "abc123",
  "privacy_mode": "strict",
  "payload_sent": { "cwe": "CWE-89", "framework": "express+pg", "pattern": "..." },
  "code_sent": false,
  "provider": "anthropic",
  "model": "claude-sonnet-4-6"
}
```

Security team can audit every payload. `code_sent: true` with an external provider = policy violation alert.

---

## 6. Scanner Stack

### 6.1 Tier 1 — Fast Scanners (pre-push, deterministic, ~5s)

| Scanner | Type | Coverage |
|---------|------|----------|
| Semgrep | SAST (pattern) | OWASP Top 10, custom rules |
| Bandit | SAST (Python) | Python-specific vulns |
| Gitleaks | Secrets | API keys, tokens, passwords |
| Trivy | SCA | Known CVEs in dependencies |

### 6.2 Tier 2 — Deep Scanners (CI/webhook, deterministic, ~2-5min)

| Scanner | Type | Coverage |
|---------|------|----------|
| FRIDAY | SAST (dataflow/taint) | Taint analysis, injection, data leaks |
| FRIDAY | Cross-boundary | Source → native addon → binary taint tracking |
| FRIDAY | Electron security | IPC exposure, context bridge, preload analysis |
| FRIDAY | Binary inspection | Zero-day detection in compiled dependencies |
| ScanCode | FOSS/License | License identification |
| ORT | License Policy | Policy evaluation, compliance |
| Syft | SBOM | CycloneDX + SPDX generation |
| Checkov | IaC (opt-in) | Terraform, K8s, CloudFormation misconfigs |

### 6.3 Tier 3 — AI Layer (on findings only, per-call cost)

| Component | Provider | Cost |
|-----------|----------|------|
| Triage (real vs false positive) | User-chosen LLM | $0.01-0.50 per finding |
| Fix suggestion generation | User-chosen LLM | Included in above |
| Fix validation | Re-scan (Tier 1/2) | $0 (deterministic) |

### 6.4 Coverage comparison

| Capability | Checkmarx | Semgrep | CodeQL | **ShiftLeft Gateway** |
|-----------|-----------|---------|--------|----------------------|
| Pattern matching | Yes | Yes | Yes | Yes (Semgrep) |
| Dataflow/taint | Yes | No (free) | Yes | **Yes (FRIDAY)** |
| Binary analysis | No | No | No | **Yes (REA)** |
| Cross-boundary taint | No | No | No | **Yes (REA)** |
| Dependency CVEs | Yes (SCA) | No | No | Yes (Trivy) |
| Secrets | No | Limited | No | Yes (Gitleaks) |
| License/FOSS | Yes (SCA) | No | No | Yes (ScanCode+ORT) |
| SBOM | Yes | No | No | Yes (Syft) |
| IaC scanning | No | Limited | No | Yes (Checkov) |
| AI fix suggestions | No | No | No | **Yes** |
| Source code privacy | N/A (SaaS) | Local | Local | **Enforced (context stripping)** |
| **License cost** | **$50-150K/yr** | **Free** | **Free (OSS only)** | **$0** |

---

## 7. Core Components

### 7.1 Pre-Push Hook (Tier 1)

```
Trigger:  git pre-push hook (installed per-repo or globally)
Input:    changed files (diff between local HEAD and remote)
Behavior:
  1. Detect languages in changed files
  2. Activate relevant Tier 1 scanners only
  3. Run scans in parallel (changed files only, not full repo)
  4. Aggregate results
  5. If findings exist:
     a. Display findings in terminal with severity
     b. Pass through Context Stripper
     c. Offer AI fix suggestions (if LLM configured)
     d. Developer reviews/applies fixes
     e. Re-scan fixed files
     f. If clean → allow push
     g. If still dirty → block push (with override flag for emergencies)
  6. If clean → push proceeds
```

### 7.2 Webhook Listener (Tier 1 + Tier 2)

```
Trigger:  GitHub/GitLab webhook (push, pull_request events)
Behavior:
  1. Receive event payload
  2. Clone/checkout relevant branch
  3. Run Tier 1 scanners (fast)
  4. Run Tier 2 scanners (FRIDAY deep analysis)
  5. Aggregate + deduplicate results
  6. Context-strip findings → AI triage (Tier 3)
  7. Route output:
     - PR comments with inline findings + AI fix suggestions
     - Jira tickets for critical/high findings
     - SARIF upload to GitHub Security tab
     - Dashboard update
```

### 7.3 Scanner Orchestrator

- Maintains a **scanner registry** (YAML config)
- Each scanner implements a common interface:
  - `scan(files, config) -> ScanResult[]`
  - `supports(language) -> bool`
  - `install_check() -> bool`
  - `tier() -> 1 | 2` (determines when it runs)
- Runs applicable scanners in **parallel** within each tier
- Scans only **changed files** (not full codebase) for speed
- Timeout per scanner (configurable, default 60s Tier 1, 300s Tier 2)
- FRIDAY integration: calls REA's analysis provider registry, uses existing session management

### 7.4 Result Aggregator

- Normalizes all scanner output to a **common finding format**
- REA Evidence records map naturally (provenance, confidence, uncertainty preserved)
- Deduplicates across scanners (same file + line + vuln type = one finding)
- Assigns unified severity (Critical / High / Medium / Low / Info)
- Fingerprints findings for tracking across scans (suppression, status)
- Supports `.shiftleft-ignore` for acknowledged false positives

### 7.5 Context Stripper

Sits between the Result Aggregator and the AI Layer. Enforces privacy policy.

```
Input:  Raw finding (code, context, metadata)
Config: privacy_mode (strict | moderate | off)

strict:
  Output: { cwe, vuln_type, framework, abstract_dataflow, file, line }
  Removes: all code, variable names, string literals, comments

moderate:
  Output: { ...strict, anonymized_snippet }
  Anonymizes: variable names → generic (var1, param2), string values → "..."

off:
  Output: full finding context including code
  Guard: ONLY allowed when provider == "ollama" (local)
         Gateway refuses to send if provider is external API

All modes: log payload to audit trail before sending
```

### 7.6 AI Triage & Fix Engine

```yaml
# User config
ai:
  provider: anthropic      # anthropic | openai | azure | bedrock | ollama
  model: claude-sonnet-4-6 # user's choice
  api_key_env: ANTHROPIC_API_KEY
  privacy_mode: strict     # strict | moderate | off
  features:
    fix_suggestions: true
    false_positive_filter: true
    severity_assessment: true
  max_tokens_per_finding: 2000
```

**LLM Orchestration: LangGraph**

The AI layer is built as a **LangGraph stateful graph** — not a simple prompt-response chain. This enables:
- Conditional routing (triage → fix → validate → retry)
- State persistence across the fix-validate-rescan loop
- Easy swap of LLM provider at any node
- Tool-calling integration (scanner re-invocation as a LangGraph tool)

```
LangGraph: FRIDAY AI Workflow
═════════════════════════════

  ┌──────────────┐
  │   START      │
  │  (finding)   │
  └──────┬───────┘
         │
         ▼
  ┌──────────────┐       ┌──────────────┐
  │   Context    │──────→│   Triage     │
  │   Stripper   │       │   Node       │
  │   (local)    │       │   (LLM)      │
  └──────────────┘       └──────┬───────┘
                                │
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
              ┌──────────┐ ┌────────┐ ┌─────────┐
              │ REAL     │ │ FALSE  │ │ UNSURE  │
              │ VULN     │ │ POS    │ │ (human) │
              └────┬─────┘ └───┬────┘ └────┬────┘
                   │           │            │
                   ▼           ▼            ▼
            ┌───────────┐  Suppress    Flag for
            │ Fix       │  & log      review
            │ Suggest   │
            │ Node (LLM)│
            └─────┬─────┘
                  │
                  ▼
            ┌───────────┐
            │ Fix       │
            │ Applier   │
            │ (local)   │
            └─────┬─────┘
                  │
                  ▼
            ┌───────────┐     ┌───────────┐
            │ Re-scan   │────→│ Validate  │
            │ (Tier 1)  │     │ Node      │
            └───────────┘     └─────┬─────┘
                                    │
                          ┌─────────┼─────────┐
                          ▼                   ▼
                    ┌──────────┐        ┌──────────┐
                    │  FIXED   │        │  RETRY   │
                    │  (done)  │        │  (loop)  │
                    └──────────┘        └──────────┘
```

```python
# LangGraph provider abstraction
from langgraph.graph import StateGraph

# LLM provider is injected — user picks in config
# Supported: Anthropic, OpenAI, Azure, Bedrock, Ollama
llm = get_provider_from_config(config.ai)

workflow = StateGraph(FindingState)
workflow.add_node("strip_context", context_stripper)
workflow.add_node("triage", triage_node(llm))
workflow.add_node("suggest_fix", fix_suggestion_node(llm))
workflow.add_node("apply_fix", local_fix_applier)
workflow.add_node("rescan", tier1_rescan)
workflow.add_node("validate", validation_node)

workflow.add_edge("strip_context", "triage")
workflow.add_conditional_edges("triage", route_by_verdict)
workflow.add_edge("suggest_fix", "apply_fix")
workflow.add_edge("apply_fix", "rescan")
workflow.add_edge("rescan", "validate")
workflow.add_conditional_edges("validate", route_by_scan_result)
```

**Flow per finding:**
1. Raw finding → Context Stripper (local) → stripped metadata
2. Stripped metadata → LangGraph triage node → LLM classifies: real / false positive / unsure
3. If real → fix suggestion node → LLM generates generic fix pattern
4. Generic fix pattern → Fix Applier (local) → maps onto actual code
5. Re-scan via Tier 1 scanners → validation node checks if resolved
6. If still failing → loop back to fix suggestion with additional context
7. Developer reviews in terminal or PR comment
8. Accept/reject → logged for local suppression rule training

### 7.7 Output Router

| Output | When | Content |
|--------|------|---------|
| Terminal | Pre-push hook | Colored findings, AI fix suggestions, pass/fail |
| PR Comment | Webhook (PR event) | Inline annotations on affected lines with fix suggestions |
| Jira | Critical/High findings | Auto-created ticket with finding details |
| SARIF | Always | Standard format, uploadable to GitHub Security tab |
| Dashboard | Always | Metrics: findings over time, fix rate, scan duration |
| Audit Log | Every LLM call | What was sent, to whom, code_sent flag |

---

## 8. Configuration

Single config file per repo (`.shiftleft.yml`) or global (`~/.shiftleft/config.yml`):

```yaml
# ─── Scanner Configuration ───────────────────────────

scanners:
  # Tier 1: Fast (pre-push)
  semgrep:
    enabled: true
    tier: 1
    rules:
      - p/owasp-top-ten
      - p/security-audit
    severity_threshold: warning

  gitleaks:
    enabled: true
    tier: 1

  bandit:
    enabled: true
    tier: 1  # auto-activates for Python files only

  trivy:
    enabled: true
    tier: 1
    scan_type: fs

  # Tier 2: Deep (CI/webhook)
  friday:
    enabled: true
    tier: 2
    analysis:
      taint_tracking: true
      binary_inspection: true
      electron_security: true
      languages: [javascript, typescript, python, java]  # FRIDAY v1
    cache_semantic_graph: true  # reuse graph for unchanged modules

  scancode:
    enabled: true
    tier: 2
    license_policy: permissive-only

  ort:
    enabled: true
    tier: 2

  syft:
    enabled: true
    tier: 2
    sbom_format: cyclonedx-json

  checkov:
    enabled: false  # opt-in for IaC repos
    tier: 2

# ─── AI Configuration ────────────────────────────────

ai:
  provider: anthropic
  model: claude-sonnet-4-6
  api_key_env: ANTHROPIC_API_KEY
  privacy_mode: strict          # strict | moderate | off
  features:
    fix_suggestions: true
    false_positive_filter: true
  audit_log: ./shiftleft-audit.jsonl

# ─── Policy ──────────────────────────────────────────

policy:
  block_on: [critical, high]
  warn_on: [medium]
  ignore: [low, info]
  emergency_override: true      # allow --force-push with audit log
  license_block: [GPL-3.0, AGPL-3.0]

# ─── Output ──────────────────────────────────────────

output:
  pr_comments: true
  jira:
    enabled: true
    project: SEC
    issue_type: Bug
  sarif: true
  dashboard_url: https://internal.dashboard/api

# ─── Hooks ───────────────────────────────────────────

hooks:
  pre_push: true               # Tier 1 only
  pre_commit: false            # opt-in
  ci_deep_scan: true           # Tier 1 + Tier 2
```

---

## 9. Cost Model

### Scan costs (Tier 1 + Tier 2): $0

All scanning is local computation. Semgrep, Gitleaks, Bandit, Trivy, FRIDAY — all run on local CPU. No API calls. No licenses.

FRIDAY's semantic graph is heavier than regex, but:
- Only runs in CI (Tier 2), not pre-push
- Scans only changed files
- Caches semantic graph for unchanged modules
- Same CPU cost as Checkmarx scan — just without the license fee

### AI costs (Tier 3): Only on findings

| Scenario | LLM calls | Cost |
|----------|----------|------|
| Clean push (no findings) | 0 | $0.00 |
| 1 finding | 1 triage + 1 fix | ~$0.01-0.10 |
| 5 findings | 5 triage + 5 fix | ~$0.05-0.50 |
| Self-hosted Ollama | Any | $0.00 (own hardware) |

### Total cost comparison

| | Checkmarx | ShiftLeft Gateway |
|---|-----------|-------------------|
| License | $50-150K/year | $0 |
| Compute (CI runner) | Included | ~$500/year (existing CI) |
| LLM API | $0 | ~$50-200/month |
| **Total/year** | **$50-150K** | **$3-5K** |

---

## 10. Developer Experience

### Install (per repo)
```bash
shiftleft init                  # creates .shiftleft.yml, installs hooks
# or
shiftleft install --global      # global git hooks for all repos
```

### Daily workflow — pre-push (Tier 1)
```bash
git push origin feature-branch

# ShiftLeft Gateway — Tier 1 scan ──────────────
# Scanning 12 changed files...
# ✓ Semgrep    (0.8s) — 0 findings
# ✓ Gitleaks   (0.2s) — 1 finding
# ✓ Bandit     (0.3s) — 0 findings (no Python files)
# ✓ Trivy      (1.1s) — 0 findings
#
# ── BLOCKED: 1 finding ───────────────────────
#
# CRITICAL  gitleaks  src/config.ts:42
#   Hardcoded AWS access key detected
#   AI Fix: Move to environment variable AWS_ACCESS_KEY_ID
#   [a]pply fix  [s]kip  [v]iew details
#
# (AI triage: strict mode — no code sent to LLM)
```

### CI deep scan (Tier 1 + Tier 2)
```bash
# ShiftLeft Gateway — Deep scan ────────────────
# Tier 1: pattern scan (2.3s) — 0 findings
# Tier 2: FRIDAY analysis...
#   Building semantic graph for 3 changed modules...
#   ✓ Taint analysis   (45s) — 1 finding
#   ✓ Binary deps      (30s) — 0 findings
#   ✓ License check    (12s) — 0 findings
#   ✓ SBOM generated
#
# ── 1 finding ────────────────────────────────
#
# HIGH  rea-sec  src/api/users.ts:87
#   SQL injection: user input flows to pg.query()
#   Dataflow: req.query.id → getUserById(id) → pg.query(sql + id)
#   AI Fix: Use parameterized query — pg.query($1, [id])
#   Confidence: 0.95
#
# → PR comment posted with inline annotation
# → SARIF uploaded to GitHub Security
```

---

## 11. Tech Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| CLI / Hooks | Python (Click/Typer) | Best scanner ecosystem, fast startup |
| Webhook Server | FastAPI | Lightweight, async, production-ready |
| LLM Orchestration | LangGraph | Stateful AI workflow — triage → fix → validate loop |
| LLM Providers | Direct SDKs via LangGraph | Anthropic, OpenAI, Azure, Bedrock, Ollama |
| Scanner Interface | Subprocess + Python API | Scanners are CLI tools; FRIDAY via Python bindings |
| Config | YAML (`.shiftleft.yml`) | Developer-friendly |
| Result Format | SARIF internally | Industry standard, GitHub-compatible |
| FRIDAY Engine | REA analysis engine (TypeScript/Node) | Existing semantic graph infrastructure |
| FRIDAY Languages | JS/TS, Python, Java (v1) | Three most common enterprise languages |
| Dashboard | Optional web UI or push to existing tools | Grafana, Datadog, etc. |

---

## 12. Constraints

- Must work offline (scanners run locally, AI layer is optional)
- Tier 1 must not add more than ~10s to a typical push
- Must support monorepos (scan only affected packages)
- Source code never sent to external LLMs (enforced by Context Stripper)
- Must provide escape hatch (emergency override with audit trail)
- FRIDAY v1 supports JS/TS, Python, Java (expand as REA adds language support)

---

## 13. Milestones

| Phase | Deliverable |
|-------|------------|
| **Phase 1** | CLI + pre-push hook with Semgrep + Gitleaks + Bandit + Trivy (Tier 1) |
| **Phase 2** | Result aggregation, dedup, severity normalization, `.shiftleft-ignore` |
| **Phase 3** | AI fix engine — Context Stripper + LangGraph workflow + privacy modes + audit log |
| **Phase 4** | Webhook server (FastAPI), PR comments, SARIF output |
| **Phase 5** | FRIDAY engine — taint source/sink definitions, security queries for JS/TS, Python, Java (Tier 2) |
| **Phase 6** | FRIDAY binary inspection — native addon analysis, compiled dep scanning |
| **Phase 7** | FOSS/license scanning (ScanCode + ORT + Syft), Jira integration |
| **Phase 8** | Dashboard, metrics, false-positive feedback loop |

---

## 14. Open Questions

- **Distribution**: pip install, Docker, or standalone binary (PyInstaller)?
- **FRIDAY post-v1 languages**: After JS/TS + Python + Java, which next? (Go, Rust, C/C++?)
- **Semantic graph caching**: File-based cache or lightweight DB (SQLite) for cross-scan reuse?
- **LangGraph persistence**: Use LangGraph's built-in checkpointing or custom state store?
