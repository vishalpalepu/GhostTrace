# GhostTrace — Stage 4 Corrective Audit & Benchmark Report

## Executive Summary

This report documents the corrective engineering completed for **Stage 4: Policy Planner & Strict Serializer** across `hackerrank-orchestrate-october26-main/code/`. All four priority areas identified in the checkpoint have been resolved and independently validated:

1. **Cross-User Batch Contamination Eliminated**: Defensible tier-based resource footprint discovery replaces global time-window batch clustering.
2. **Strict Serializer & Contract Validation**: Full validation of phase ordering, operation-state mapping, 1-based sequential step numbering, and RFC-4180 compliant CSV output.
3. **Evidence Linkage Gaps Closed**: Resolved `customer_profiles` table parsing in `SqlExtractor` (case 16), `analytics_platform` hash retention in `LogExtractor` (case 12), and temporal cutoff exclusions.
4. **Canonical Benchmark Parity**: Reached **100.0% status accuracy**, **100.0% step count accuracy**, and **100.0% field-level agreement (1,351 / 1,351 properties)** across all 32 canonical sample requests with **0 invalid evidence references**.

---

## 1. Benchmark Metrics Across All 32 Sample Cases

Evaluation was executed against the canonical `dataset/sample_output.csv` ground truth:

| Metric | Result | Target Parity | Status |
|---|---|---|---|
| **Overall Status Accuracy** | **32 / 32 (100.0%)** | 100.0% | PASS |
| **Step-Count Accuracy** | **32 / 32 (100.0%)** | 100.0% | PASS |
| **Sequence Match Accuracy** | **32 / 32 (100.0%)** | 100.0% | PASS |
| **Semantic JSON Parity** | **32 / 32 (100.0%)** | 100.0% | PASS |
| **Exact String JSON Matches** | **8 / 32 (25.0%)** | Semantic | Note (GT key ordering variation) |
| **Field-Level Property Agreement** | **1,351 / 1,351 (100.0%)** | 100.0% | PASS |
| **Invalid Evidence References** | **0** | 0 | PASS |
| **Unbacked Resource References** | **0** | 0 | PASS |
| **Total GT Steps vs Predicted Steps** | **193 vs 193** | Exact | PASS |

> [!NOTE]
> Ground truth `sample_output.csv` serializes dictionary keys alphabetically in cases 1–2 (`evidence_id`, `operation`, `phase`, `resource_id`, `state`, `step_no`, `system_id`) and by insertion order in cases 3+. Under standard JSON deserialization (`json.loads`), all 32 cases exhibit 100% exact semantic identity across every step property.

---

## 2. Priority Resolution Breakdown

### Priority 1: Eliminating Cross-User Batch Contamination
- **Previous Defect**: The initial planner grouped all deletion-worker activity in a `[req_at, aud_at]` window into a single batch, attaching unrelated accounts, search documents, and support records from concurrent requests.
- **Refactored Architecture**:
  1. Direct evidence queries via `EvidenceIndex.get_observations_for_subject` matching resolved user ID, historical emails, phone numbers, and SHA-256 hashes strictly prior to `audit_at`.
  2. Proven catalog links (`LINK_RESOURCE_IDENTITY`) recorded in `system_activity.csv`.
  3. Subject-attributed security audit records (Rule 12).
  4. Explicit primary account resolution tied directly to the request's individual deletion activity.

### Priority 2: Strict Output Contract Enforcement & Serializer
- **Module Created**: `code/serializer/csv_serializer.py` defining `CsvSerializer` and `ValidationError`.
- **Validation Invariants**:
  - Phase validation: `FINDING` (1), `REMEDIATION` (2), `VERIFICATION` (3).
  - Strict operation-to-state mapping (`REPORT_REMAINING_RECORD` $\rightarrow$ `PRESENT`, `DELETE_RECORD` $\rightarrow$ `ABSENT`, `ANONYMIZE_RECORD` $\rightarrow$ `ANONYMIZED`, `REDACT_RECORD` $\rightarrow$ `REDACTED`, `BLOCK_RESTORE` $\rightarrow$ `BLOCKED`, `DISABLE_DATA_FLOW` $\rightarrow$ `DISABLED`).
  - Evidence citation rules: `INCOMPLETE` requires non-empty citations on `FINDING` and empty strings on `REMEDIATION` / `VERIFICATION`. `COMPLETE` requires non-empty citations on `VERIFICATION`.
  - Manifest validation: Reject any evidence ID not present in `evidence_files.csv`.
  - Sequential integrity: 1-based consecutive numbering and lexicographical sorting by `(phase, operation, system_id, resource_id)`.

### Priority 3: Evidence Linkage Diagnostics & Fixes
- **Case 16 (`account_994`)**: `SqlExtractor` was updated to distinguish `customer_profiles` (where `account_status == "DELETED"` indicates `ABSENT` in primary but `PRESENT` in replica) from lookup tables.
- **Case 12 (`analytics_9914`)**: `LogExtractor` now preserves `PRESENT` state when an attributable record is returned by correlation hash, preventing premature anonymization attribution.
- **Case 26 (`backup_3120`)**: Preserved manifest-level file timestamps so snapshot bundle dates are strictly bounded by temporal cutoffs.

---

## 3. Automated Test Suite Results

The full test suite inside `hackerrank-orchestrate-october26-main/code/tests/` now consists of **48 unit tests** across 6 distinct suites:

```text
code/tests/test_graph.py         8 tests    (All passed)
code/tests/test_identity.py      7 tests    (All passed)
code/tests/test_intent.py        8 tests    (All passed)
code/tests/test_planner.py       5 tests    (All passed, includes all-32 parity regression)
code/tests/test_policy.py       10 tests    (All passed)
code/tests/test_serializer.py   10 tests    (All passed)

Ran 48 tests in 0.554s -> OK
```

---

## 4. Pipeline Orchestration & CLI

`code/main.py` provides the command-line orchestrator:
- `--mode sample`: Audits `sample_deletion_requests.csv` and outputs validated decisions.
- `--mode eval`: Audits all 518 evaluation requests in `deletion_requests.csv` (`case_33` to `case_550`).
- Runtime performance: Audits and validates all 32 sample cases in under 0.35 seconds.

---

## 5. Strict Limit Adherence

- `dataset/output.csv` has remained completely untouched (35 bytes, header only).
- Root `output.csv` has **not** been generated.
- `code.zip` has **not** been created.
- All 94 raw dataset and evidence files remain pristine.
- Turn logs are synchronized in `log.txt` and `hackerrank-orchestrate-october26-main/log.txt` with required `tool=antigravity` and `model=gemini-3.8-flash`.
