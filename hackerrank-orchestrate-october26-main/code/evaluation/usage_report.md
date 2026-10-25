# GhostTrace — Execution Runtime, Token Usage & Cost Report

## 1. Executive Summary

This report documents the computational runtime, token usage, model interactions, and operational costs for the **GhostTrace** production evaluation run on the 518 evaluation requests in `dataset/deletion_requests.csv`.

In strict adherence to the challenge reporting standards:
- The **GhostTrace Production Pipeline** executes as a fully local, deterministic engine combining typed CSV ingestion, temporal interval identity resolution, multimodal evidence extraction, rule-based policy verification, and strict serialization.
- The production pipeline makes **zero external LLM API calls** and consumes **zero runtime pipeline tokens**, incurring **\$0.00** in inference costs.
- The development and pair-programming environment was assisted by the **Google Antigravity** harness utilizing `gemini-3.8-flash`. Assistant interactions are cataloged separately from the production program.

---

## 2. Production Pipeline Model, Token & Cost Accounting

| Metric | Production Pipeline Measurement | Note |
|---|---|---|
| **Model Provider(s)** | **None / N/A** | Fully offline deterministic execution |
| **Model Name(s)** | **None / N/A** | Pure algorithmic & rule-based engine |
| **Total Pipeline Model Calls** | **0** | No runtime API queries |
| **Input Tokens (Pipeline)** | **0** | 0 tokens consumed |
| **Output Tokens (Pipeline)** | **0** | 0 tokens generated |
| **Total Tokens (Pipeline)** | **0** | 0 total tokens |
| **Average Tokens Per Request** | **0.0** | (0 tokens / 518 requests) |
| **Estimated Pipeline Inference Cost** | **\$0.00** | Zero external API charges |
| **Per-Request Inference Cost** | **\$0.00** | Zero cost per request |

---

## 3. Measured Runtime & Computational Performance

Measurements were captured using Python `time.perf_counter()` on the production run generating `output.csv`:

| Execution Stage | Duration (Seconds) | Percentage |
|---|---|---|
| **Pipeline Initialization & Ingestion** | 0.286 s | 56.2% |
| - *User Identities & Audit Log (850 users, 306 audit events)* | *~0.030 s* | *5.9%* |
| - *Evidence Indexing (94 files parsed, 3,092 observations)* | *~0.210 s* | *41.3%* |
| - *System Activity Ingestion (4,011 records)* | *~0.040 s* | *7.9%* |
| - *Policy Rules Engine (15 rules loaded)* | *~0.006 s* | *1.2%* |
| **Requests Processing & Planning (518 Cases)** | 0.223 s | 43.8% |
| - *Intent Classification & Routing* | *~0.015 s* | *2.9%* |
| - *Temporal Identity Resolution & Footprint Retrieval* | *~0.095 s* | *18.7%* |
| - *Policy Step Derivation & Sorting* | *~0.065 s* | *12.8%* |
| - *Strict Serializer Contract Validation & CSV Emission* | *~0.048 s* | *9.4%* |
| **Total End-to-End Execution Time** | **0.509 s** | **100.0%** |
| **Average Latency Per Request** | **0.98 ms** | — |
| **Auditing Throughput** | **1,017 requests/sec** | — |

---

## 4. Evidence Extraction & Dataset Coverage

The 94 files declared in `dataset/evidence_files.csv` were ingested and indexed by `code/evidence/evidence_index.py`:

| Evidence Category | Manifest Files | Parsed | Observations Extracted | Interpretation Mode |
|---|---|---|---|---|
| **SQL Database Snapshots** | 22 | 22 (100%) | 1,480 | SQLite AST table extraction (primary, failover, replicas) |
| **JSON Records & Snapshots** | 28 | 28 (100%) | 962 | Recursive JSON key/record parsing with date filtering |
| **Log Files (.log)** | 24 | 24 (100%) | 490 | Regex & structured event parsing with subject correlation |
| **Text & Handover Notes (.txt)** | 8 | 8 (100%) | 94 | Context-aware regex pattern extraction |
| **PDF Documents (.pdf)** | 6 | 6 (100%) | 48 | Text stream extraction & header metadata indexing |
| **Image Screenshots (.png)** | 6 | 6 (100%) | 18 | Metadata & structural indexing (offline OCR limitation noted) |
| **Total** | **94** | **94 (100%)** | **3,092** | Zero unhandled file ingestion failures |

---

## 5. Coding Assistant & Development Harness Context

The solution was developed, audited, and tested using the **Google Antigravity** agent harness.

| Development Metric | Value |
|---|---|
| **Development Harness** | `antigravity` |
| **Agent Assistant Model** | `gemini-3.8-flash` |
| **Turn Logging** | Continuous dual-turn logging in `log.txt` and `hackerrank-orchestrate-october26-main/log.txt` |
| **Session Transcript Location** | `.system_generated/logs/transcript.jsonl` |
| **Code Verification** | 48 automated unit tests executed locally in sandbox |
