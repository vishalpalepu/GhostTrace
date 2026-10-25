"""Extractor for log evidence files (.log)."""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..ingestion.csv_loader import parse_iso8601
from .models import ExtractedObservation


class LogExtractor:
    """Extracts provenance-tracked observations from structured and key-value logs."""

    @staticmethod
    def extract_from_file(
        file_id: str,
        file_path: Path,
        captured_at: datetime,
    ) -> List[ExtractedObservation]:
        observations: List[ExtractedObservation] = []
        if not file_path.exists():
            return observations

        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()

        # Pass 1: Build trace_context to correlate multi-line readback traces
        trace_context: Dict[str, Dict[str, Optional[str]]] = {}
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Check JSON
            json_start = line.find("{")
            if json_start != -1 and line.endswith("}"):
                try:
                    obj = json.loads(line[json_start:])
                    tid = obj.get("trace_id") or obj.get("requestId")
                    if tid:
                        if tid not in trace_context:
                            trace_context[tid] = {"email": None, "user_id": None}
                        lk = obj.get("lookup_key") or obj.get("subject_ref") or obj.get("correlation_key") or ""
                        if "@" in lk:
                            trace_context[tid]["email"] = lk.strip().lower()
                        elif str(lk).startswith("user_"):
                            trace_context[tid]["user_id"] = str(lk).strip()
                        if obj.get("email"):
                            trace_context[tid]["email"] = str(obj["email"]).strip().lower()
                        if obj.get("user_id"):
                            trace_context[tid]["user_id"] = str(obj["user_id"]).strip()
                        if obj.get("customer_reference") and obj["customer_reference"] != "null":
                            trace_context[tid]["user_id"] = str(obj["customer_reference"]).strip()
                        if obj.get("customer_email") and obj["customer_email"] != "null":
                            trace_context[tid]["email"] = str(obj["customer_email"]).strip().lower()
                except Exception:
                    pass
                continue

            # Check KV
            tokens = line.split()
            tid = None
            kv_lk = ""
            for tok in tokens:
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    k = k.strip()
                    v = v.strip("\"'")
                    if k in ("trace_id", "requestId"):
                        tid = v
                    elif k in ("lookup_key", "correlation_key", "subject_reference", "subject_ref", "subject_key", "matched_value"):
                        kv_lk = v
                    elif k in ("email", "customer_email", "requester_email") and "@" in v:
                        kv_lk = v
            if tid:
                if tid not in trace_context:
                    trace_context[tid] = {"email": None, "user_id": None, "hash": None}
                if "@" in kv_lk:
                    trace_context[tid]["email"] = kv_lk.strip().lower()
                elif kv_lk.startswith("user_"):
                    trace_context[tid]["user_id"] = kv_lk.strip()
                elif len(kv_lk) == 64 and all(c in "0123456789abcdefABCDEF" for c in kv_lk):
                    trace_context[tid]["hash"] = kv_lk.strip().lower()

        # Pass 2: Extract observations using correlated trace_context
        for line_idx, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue

            # Case A: Line begins with ISO timestamp followed by JSON
            json_start = line.find("{")
            if json_start != -1 and line.endswith("}"):
                ts_part = line[:json_start].strip()
                json_part = line[json_start:]
                try:
                    obj = json.loads(json_part)
                    line_time = parse_iso8601(ts_part) if ts_part else captured_at
                    obs = LogExtractor._parse_json_log_entry(
                        file_id=file_id,
                        source_path=str(file_path),
                        line_time=line_time,
                        captured_at=captured_at,
                        entry=obj,
                        trace_context=trace_context,
                    )
                    if obs:
                        observations.append(obs)
                    continue
                except Exception:
                    pass

            # Case B: Key-value log line
            obs_kv = LogExtractor._parse_kv_log_line(
                file_id=file_id,
                source_path=str(file_path),
                captured_at=captured_at,
                line=line,
                trace_context=trace_context,
            )
            if obs_kv:
                observations.append(obs_kv)

        return observations

    @staticmethod
    def _parse_json_log_entry(
        file_id: str,
        source_path: str,
        line_time: Optional[datetime],
        captured_at: datetime,
        entry: Dict[str, Any],
        trace_context: Optional[Dict[str, Dict[str, Optional[str]]]] = None,
    ) -> Optional[ExtractedObservation]:
        res_id = entry.get("resource_id")
        if not res_id:
            return None

        service = entry.get("service") or entry.get("logger") or "unknown"
        event = entry.get("event") or ""
        email = (entry.get("email") or entry.get("lookup_key") or "").lower() or None
        subj_id = entry.get("user_id") or entry.get("customer_reference")

        # Correlate with trace context if needed
        tid = entry.get("trace_id") or entry.get("requestId")
        if trace_context and tid and tid in trace_context:
            tinfo = trace_context[tid]
            if not email and tinfo.get("email"):
                email = tinfo["email"]
            if not subj_id and tinfo.get("user_id"):
                subj_id = tinfo["user_id"]

        # Determine state
        state = "PRESENT"
        cat = None

        if "status_code" in entry and entry["status_code"] == 404:
            state = "ABSENT"
        elif "rows" in entry and entry["rows"] == 0:
            state = "ABSENT"
        elif "enabled" in entry:
            service = "integration_service"
            state = "ACTIVE" if entry["enabled"] else "DISABLED"
        elif "restore_allowed" in entry:
            service = "backup_service"
            cat = "BACKUP_ARCHIVE"
            state = "ACTIVE" if entry["restore_allowed"] else "BLOCKED"
        elif "deletion_block" in entry:
            service = "backup_service"
            cat = "BACKUP_ARCHIVE"
            state = "BLOCKED" if entry["deletion_block"] else "ACTIVE"

        if service == "account_service":
            cat = "USER_PROFILE"
        elif service == "search_service":
            cat = "SEARCH_INDEX_ENTRY"
        elif service == "analytics_platform":
            cat = "ANALYTICS_PROFILE"
            if not subj_id and not email and not subj_hash:
                state = "ANONYMIZED"
        elif service in ("support_platform", "support_replica"):
            service = "support_platform"
            cat = "SUPPORT_MESSAGE"
        elif service == "backup_service":
            cat = "BACKUP_ARCHIVE"

        if subj_hash:
            kv["subject_hash"] = subj_hash

        return ExtractedObservation(
            file_id=file_id,
            source_path=source_path,
            system_id=service,
            resource_id=res_id,
            data_category=cat,
            observed_state=state,
            subject_id=subj_id,
            subject_email=email,
            subject_phone=None,
            observation_time=line_time,
            captured_at=captured_at,
            extraction_method="LOG_PARSE",
            details=entry,
        )

    @staticmethod
    def _parse_kv_log_line(
        file_id: str,
        source_path: str,
        captured_at: datetime,
        line: str,
        trace_context: Optional[Dict[str, Dict[str, Optional[str]]]] = None,
    ) -> Optional[ExtractedObservation]:
        # Split tokens
        tokens = line.split()
        if not tokens:
            return None

        line_time = None
        first_token = tokens[0]
        if first_token.endswith("Z") and ("T" in first_token):
            line_time = parse_iso8601(first_token)
            tokens = tokens[1:]

        kv: Dict[str, str] = {}
        for tok in tokens:
            if "=" in tok:
                k, v = tok.split("=", 1)
                kv[k.strip()] = v.strip("\"'")

        res_id = kv.get("resource_id")
        if not res_id:
            return None

        service = kv.get("service") or kv.get("system") or "unknown"
        if service == "support_replica":
            service = "support_platform"

        # Lookup key / identity
        lookup_key = kv.get("lookup_key") or kv.get("customer_reference") or kv.get("email") or kv.get("subject_key") or kv.get("matched_value") or ""
        email = None
        subj_id = None
        subj_hash = None
        if "@" in lookup_key:
            email = lookup_key.lower()
        elif lookup_key.startswith("user_"):
            subj_id = lookup_key
        elif len(lookup_key) == 64 and all(c in "0123456789abcdefABCDEF" for c in lookup_key):
            subj_hash = lookup_key.lower()

        if "correlation_key" in kv:
            ck = kv["correlation_key"].strip("\"'")
            if len(ck) == 64 and all(c in "0123456789abcdefABCDEF" for c in ck):
                subj_hash = ck.lower()

        if "customer_email" in kv and kv["customer_email"] != "null":
            email = kv["customer_email"].lower()
        if "customer_reference" in kv and kv["customer_reference"] != "null":
            subj_id = kv["customer_reference"]

        # Correlate with trace context if needed
        tid = kv.get("trace_id") or kv.get("requestId")
        if trace_context and tid and tid in trace_context:
            tinfo = trace_context[tid]
            if not email and tinfo.get("email"):
                email = tinfo["email"]
            if not subj_id and tinfo.get("user_id"):
                subj_id = tinfo["user_id"]
            if not subj_hash and tinfo.get("hash"):
                subj_hash = tinfo["hash"]

        # State determination
        state = "PRESENT"
        cat = None

        http_status = kv.get("http_status")
        rows = kv.get("rows")
        if http_status == "404" or rows == "0":
            state = "ABSENT"
        elif "enabled" in kv:
            service = "integration_service"
            enabled = kv["enabled"].lower() in ("true", "1")
            state = "ACTIVE" if enabled else "DISABLED"
        elif "restore_allowed" in kv:
            service = "backup_service"
            cat = "BACKUP_ARCHIVE"
            restore_allowed = kv["restore_allowed"].lower() in ("true", "1")
            state = "ACTIVE" if restore_allowed else "BLOCKED"
        elif "deletion_block" in kv:
            service = "backup_service"
            cat = "BACKUP_ARCHIVE"
            deletion_block = kv["deletion_block"].lower() in ("true", "1")
            state = "BLOCKED" if deletion_block else "ACTIVE"

        if service == "account_service":
            cat = "USER_PROFILE"
        elif service == "search_service":
            cat = "SEARCH_INDEX_ENTRY"
        elif service == "analytics_platform":
            cat = "ANALYTICS_PROFILE"
            if not subj_id and not email and not subj_hash:
                state = "ANONYMIZED"
        elif service in ("support_platform", "support_replica"):
            service = "support_platform"
            cat = "SUPPORT_MESSAGE"
        elif service == "backup_service":
            cat = "BACKUP_ARCHIVE"

        if subj_hash:
            kv["subject_hash"] = subj_hash

        return ExtractedObservation(
            file_id=file_id,
            source_path=source_path,
            system_id=service,
            resource_id=res_id,
            data_category=cat,
            observed_state=state,
            subject_id=subj_id,
            subject_email=email,
            subject_phone=None,
            observation_time=line_time,
            captured_at=captured_at,
            extraction_method="LOG_PARSE",
            details=kv,
        )
