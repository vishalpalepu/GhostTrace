"""Extractor for JSON evidence files (.json)."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..ingestion.csv_loader import parse_iso8601
from .models import ExtractedObservation


class JsonExtractor:
    """Extracts provenance-tracked observations from JSON evidence snapshots."""

    @staticmethod
    def extract_from_file(
        file_id: str,
        file_path: Path,
        captured_at: datetime,
    ) -> List[ExtractedObservation]:
        observations: List[ExtractedObservation] = []
        if not file_path.exists():
            return observations

        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
        except Exception as e:
            observations.append(
                ExtractedObservation(
                    file_id=file_id,
                    source_path=str(file_path),
                    system_id="unknown",
                    resource_id=f"error_{file_id}",
                    observed_state="UNKNOWN",
                    captured_at=captured_at,
                    extraction_method="JSON_PARSE",
                    uncertainty=f"Failed to parse JSON: {e}",
                )
            )
            return observations

        # Case 1: Service resource exports (e.g. service_resource_export_*.json)
        if "service_exports" in data:
            exports = data.get("service_exports", {})
            for sys_name, sys_content in exports.items():
                if not isinstance(sys_content, dict):
                    continue
                for coll_name, items in sys_content.items():
                    if not isinstance(items, list):
                        continue
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        res_id = item.get("resource_id") or ""
                        subj_id = item.get("customer_reference") or item.get("user_id") or item.get("subject_reference")
                        email = (item.get("customer_email") or item.get("owner_email") or item.get("requester_email") or item.get("email") or "").lower() or None
                        if not email and item.get("query") and "@" in item.get("query"):
                            email = item.get("query").lower().strip()
                        if not email and isinstance(item.get("hits"), dict):
                            docs = item.get("hits", {}).get("documents", [])
                            if docs and isinstance(docs[0], dict):
                                doc_email = docs[0].get("email")
                                if doc_email:
                                    email = doc_email.lower().strip()
                                if not subj_id:
                                    subj_id = docs[0].get("customer_reference")
                        phone = item.get("phone") or item.get("owner_phone") or item.get("requester_phone")
                        obs_time = parse_iso8601(item["observed_at"]) if "observed_at" in item and item["observed_at"] else None

                        cat = None
                        state = "PRESENT"

                        if sys_name == "account_service":
                            cat = "USER_PROFILE"
                            code = item.get("status_code")
                            prof = item.get("profile")
                            if code == 404 or prof is None or (isinstance(prof, dict) and prof.get("account_status") == "DELETED"):
                                state = "ABSENT"
                            else:
                                state = "PRESENT"
                                if isinstance(prof, dict):
                                    subj_id = subj_id or prof.get("customer_reference") or prof.get("user_id")
                                    email = email or (prof.get("email") or "").lower() or None
                                    phone = phone or prof.get("phone")
                        elif sys_name == "analytics_platform":
                            cat = "ANALYTICS_PROFILE"
                            if not subj_id and not email and not phone:
                                state = "ANONYMIZED"
                            else:
                                state = "PRESENT"
                        elif sys_name == "search_service":
                            cat = "SEARCH_INDEX_ENTRY"
                            hits = item.get("hits")
                            if isinstance(hits, dict) and hits.get("total", 1) == 0:
                                state = "ABSENT"
                            else:
                                state = "PRESENT"
                        elif sys_name == "support_platform":
                            cat = "SUPPORT_MESSAGE"
                            has_pii = bool(item.get("requester_email") or item.get("requester_name") or item.get("requester_phone") or item.get("email") or item.get("name") or item.get("phone"))
                            if item.get("redacted") or not has_pii:
                                state = "REDACTED"
                            else:
                                state = "PRESENT"
                        elif sys_name == "export_service":
                            cat = "USER_EXPORT"
                            state = "PRESENT"
                        elif sys_name == "integration_service":
                            enabled = bool(item.get("enabled"))
                            state = "ACTIVE" if enabled else "DISABLED"
                        elif sys_name == "backup_service":
                            cat = "BACKUP_ARCHIVE"
                            restore_allowed = bool(item.get("restore_allowed"))
                            state = "ACTIVE" if restore_allowed else "BLOCKED"
                        elif sys_name == "security_service":
                            cat = "SECURITY_AUDIT_LOG"
                            state = "PRESENT"

                        observations.append(
                            ExtractedObservation(
                                file_id=file_id,
                                source_path=str(file_path),
                                system_id=sys_name,
                                resource_id=res_id,
                                data_category=cat,
                                observed_state=state,
                                subject_id=subj_id,
                                subject_email=email,
                                subject_phone=phone,
                                observation_time=obs_time,
                                captured_at=captured_at,
                                extraction_method="JSON_PARSE",
                                details={"collection": coll_name, "raw": item},
                            )
                        )

        # Case 2: Customer data snapshot bundles (e.g. customer_data_snapshot_bundle_*.json)
        elif "snapshots" in data:
            snapshots = data.get("snapshots", [])
            for snap in snapshots:
                data_store = snap.get("data_store", "unknown")
                collection = snap.get("collection", "")
                snap_captured_at = parse_iso8601(snap["captured_at"]) if "captured_at" in snap and snap["captured_at"] else captured_at
                records = snap.get("records", [])

                for rec in records:
                    if not isinstance(rec, dict):
                        continue
                    res_id = rec.get("resource_id") or ""
                    subj_id = rec.get("customer_reference") or rec.get("user_id") or rec.get("subject_reference")
                    email = (rec.get("email") or rec.get("customer_email") or rec.get("requester_email") or "").lower() or None
                    phone = rec.get("phone") or rec.get("requester_phone")
                    obs_time = parse_iso8601(rec["updated_at"]) if "updated_at" in rec and rec["updated_at"] else snap_captured_at

                    cat = None
                    state = "PRESENT"

                    if data_store == "account_service":
                        cat = "USER_PROFILE"
                        status = rec.get("account_status")
                        state = "ABSENT" if status == "DELETED" else "PRESENT"
                    elif data_store == "identity_service" and "tombstone" in res_id:
                        cat = "ACCOUNT_TOMBSTONE"
                        has_direct_pii = bool(rec.get("name") or email or phone or rec.get("email_hash"))
                        state = "PRESENT" if has_direct_pii else "REDACTED"
                    elif data_store == "search_service":
                        cat = "SEARCH_INDEX_ENTRY"
                        state = "PRESENT"
                    elif data_store == "analytics_platform":
                        cat = "ANALYTICS_PROFILE"
                        state = "ANONYMIZED" if (not subj_id and not email and not phone) else "PRESENT"
                    elif data_store == "support_platform":
                        cat = "SUPPORT_MESSAGE"
                        state = "REDACTED" if rec.get("redacted") else "PRESENT"
                    elif data_store == "backup_service":
                        cat = "BACKUP_ARCHIVE"
                        restore_allowed = bool(rec.get("restore_allowed"))
                        state = "ACTIVE" if restore_allowed else "BLOCKED"
                    elif data_store == "security_service":
                        cat = "SECURITY_AUDIT_LOG"
                        state = "PRESENT"
                    elif data_store == "integration_service":
                        enabled = bool(rec.get("enabled"))
                        state = "ACTIVE" if enabled else "DISABLED"

                    observations.append(
                        ExtractedObservation(
                            file_id=file_id,
                            source_path=str(file_path),
                            system_id=data_store,
                            resource_id=res_id,
                            data_category=cat,
                            observed_state=state,
                            subject_id=subj_id,
                            subject_email=email,
                            subject_phone=phone,
                            observation_time=obs_time,
                            captured_at=captured_at,
                            extraction_method="JSON_PARSE",
                            details={"collection": collection, "raw": rec},
                        )
                    )

        # Case 3: Flat record list files (e.g. customer_export_jobs_*.json, customer_analytics_report_*.json)
        elif "records" in data:
            records = data.get("records", [])
            raw_origin = data.get("origin") or data.get("source") or "export_service"
            if "export" in raw_origin.lower():
                origin = "export_service"
            elif "analytics" in raw_origin.lower():
                origin = "analytics_platform"
            else:
                origin = raw_origin
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                res_id = rec.get("resource_id") or rec.get("job_id") or ""
                subj_id = rec.get("customer_reference") or rec.get("user_id")
                email = (rec.get("owner_email") or rec.get("email") or "").lower() or None
                phone = rec.get("owner_phone") or rec.get("phone")
                obs_time = parse_iso8601(rec["created_at"]) if "created_at" in rec and rec["created_at"] else captured_at

                cat = "USER_EXPORT" if "export" in origin.lower() else "ANALYTICS_PROFILE"
                state = "ANONYMIZED" if (rec.get("is_anonymized") or (not subj_id and not email)) else "PRESENT"

                observations.append(
                    ExtractedObservation(
                        file_id=file_id,
                        source_path=str(file_path),
                        system_id=origin,
                        resource_id=res_id,
                        data_category=cat,
                        observed_state=state,
                        subject_id=subj_id,
                        subject_email=email,
                        subject_phone=phone,
                        observation_time=obs_time,
                        captured_at=captured_at,
                        extraction_method="JSON_PARSE",
                        details={"origin": origin, "raw": rec},
                    )
                )

        return observations
