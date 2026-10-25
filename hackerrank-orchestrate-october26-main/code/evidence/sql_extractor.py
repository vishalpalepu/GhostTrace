"""Extractor for SQL database snapshots (.sql)."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..ingestion.csv_loader import parse_iso8601
from .models import ExtractedObservation


class SqlExtractor:
    """Executes and extracts observations from SQLite-compatible SQL snapshots."""

    @staticmethod
    def extract_from_file(
        file_id: str,
        file_path: Path,
        captured_at: datetime,
    ) -> List[ExtractedObservation]:
        observations: List[ExtractedObservation] = []
        if not file_path.exists():
            return observations

        conn = sqlite3.connect(":memory:")
        try:
            sql_text = file_path.read_text(encoding="utf-8")
            conn.executescript(sql_text)
            cursor = conn.cursor()

            # Inspect available tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = set(row[0] for row in cursor.fetchall())

            # 1. customer_profiles / customer_profiles_primary / customer_profiles_failover_replica
            for tname in ["customer_profiles", "customer_profiles_primary", "customer_profiles_failover_replica"]:
                if tname in tables:
                    cursor.execute(f"SELECT * FROM \"{tname}\";")
                    col_names = [d[0] for d in cursor.description]
                    for row in cursor.fetchall():
                        r = dict(zip(col_names, row))
                        res_id = r.get("resource_id") or ""
                        subj_id = r.get("customer_reference") or r.get("user_id")
                        email = (r.get("email") or "").lower() or None
                        phone = r.get("phone")
                        status = r.get("account_status", "ACTIVE")
                        updated_at = parse_iso8601(r["updated_at"]) if "updated_at" in r and r["updated_at"] else None

                        state = "ABSENT" if status == "DELETED" else "PRESENT"
                        observations.append(
                            ExtractedObservation(
                                file_id=file_id,
                                source_path=str(file_path),
                                system_id="account_service",
                                resource_id=res_id,
                                data_category="USER_PROFILE",
                                observed_state=state,
                                subject_id=subj_id,
                                subject_email=email,
                                subject_phone=phone,
                                observation_time=updated_at,
                                captured_at=captured_at,
                                extraction_method="SQL_EXEC",
                                details={"table": tname, "account_status": status, "raw": r},
                            )
                        )

            # 2. customer_search_documents / search_documents_primary
            if "customer_search_documents" in tables:
                cursor.execute("SELECT * FROM customer_search_documents;")
                col_names = [d[0] for d in cursor.description]
                for row in cursor.fetchall():
                    r = dict(zip(col_names, row))
                    res_id = r.get("resource_id") or ""
                    subj_id = r.get("customer_reference")
                    email = (r.get("email") or "").lower() or None
                    phone = r.get("phone")
                    updated_at = parse_iso8601(r["updated_at"]) if "updated_at" in r and r["updated_at"] else None
                    observations.append(
                        ExtractedObservation(
                            file_id=file_id,
                            source_path=str(file_path),
                            system_id="search_service",
                            resource_id=res_id,
                            data_category="SEARCH_INDEX_ENTRY",
                            observed_state="PRESENT",
                            subject_id=subj_id,
                            subject_email=email,
                            subject_phone=phone,
                            observation_time=updated_at,
                            captured_at=captured_at,
                            extraction_method="SQL_EXEC",
                            details={"table": "customer_search_documents", "raw": r},
                        )
                    )

            if "search_documents_primary" in tables:
                cursor.execute("SELECT * FROM search_documents_primary;")
                col_names = [d[0] for d in cursor.description]
                for row in cursor.fetchall():
                    r = dict(zip(col_names, row))
                    res_id = r.get("resource_id") or ""
                    email = (r.get("email") or "").lower() or None
                    indexed_at = parse_iso8601(r["indexed_at"]) if "indexed_at" in r and r["indexed_at"] else None
                    observations.append(
                        ExtractedObservation(
                            file_id=file_id,
                            source_path=str(file_path),
                            system_id="search_service",
                            resource_id=res_id,
                            data_category="SEARCH_INDEX_ENTRY",
                            observed_state="PRESENT",
                            subject_id=None,
                            subject_email=email,
                            subject_phone=None,
                            observation_time=indexed_at,
                            captured_at=captured_at,
                            extraction_method="SQL_EXEC",
                            details={"table": "search_documents_primary", "raw": r},
                        )
                    )

            # 3. customer_analytics_profiles
            if "customer_analytics_profiles" in tables:
                cursor.execute("SELECT * FROM customer_analytics_profiles;")
                col_names = [d[0] for d in cursor.description]
                for row in cursor.fetchall():
                    r = dict(zip(col_names, row))
                    res_id = r.get("resource_id") or ""
                    subj_id = r.get("customer_reference")
                    email = (r.get("email") or "").lower() or None
                    phone = r.get("phone")
                    updated_at = parse_iso8601(r["updated_at"]) if "updated_at" in r and r["updated_at"] else None

                    is_attributable = bool(subj_id or email or phone)
                    state = "PRESENT" if is_attributable else "ANONYMIZED"
                    observations.append(
                        ExtractedObservation(
                            file_id=file_id,
                            source_path=str(file_path),
                            system_id="analytics_platform",
                            resource_id=res_id,
                            data_category="ANALYTICS_PROFILE",
                            observed_state=state,
                            subject_id=subj_id,
                            subject_email=email,
                            subject_phone=phone,
                            observation_time=updated_at,
                            captured_at=captured_at,
                            extraction_method="SQL_EXEC",
                            details={"table": "customer_analytics_profiles", "raw": r},
                        )
                    )

            # 4. support_records
            if "support_records" in tables:
                cursor.execute("SELECT * FROM support_records;")
                col_names = [d[0] for d in cursor.description]
                for row in cursor.fetchall():
                    r = dict(zip(col_names, row))
                    res_id = r.get("resource_id") or ""
                    subj_id = r.get("customer_reference")
                    email = (r.get("requester_email") or "").lower() or None
                    phone = r.get("requester_phone")
                    updated_at = parse_iso8601(r["updated_at"]) if "updated_at" in r and r["updated_at"] else None
                    observations.append(
                        ExtractedObservation(
                            file_id=file_id,
                            source_path=str(file_path),
                            system_id="support_platform",
                            resource_id=res_id,
                            data_category="SUPPORT_MESSAGE",
                            observed_state="PRESENT",
                            subject_id=subj_id,
                            subject_email=email,
                            subject_phone=phone,
                            observation_time=updated_at,
                            captured_at=captured_at,
                            extraction_method="SQL_EXEC",
                            details={"table": "support_records", "has_shared_context": True, "raw": r},
                        )
                    )

            # 5. customer_exports
            if "customer_exports" in tables:
                cursor.execute("SELECT * FROM customer_exports;")
                col_names = [d[0] for d in cursor.description]
                for row in cursor.fetchall():
                    r = dict(zip(col_names, row))
                    res_id = r.get("resource_id") or ""
                    subj_id = r.get("customer_reference")
                    email = (r.get("owner_email") or "").lower() or None
                    phone = r.get("owner_phone")
                    updated_at = parse_iso8601(r["updated_at"]) if "updated_at" in r and r["updated_at"] else None
                    observations.append(
                        ExtractedObservation(
                            file_id=file_id,
                            source_path=str(file_path),
                            system_id="export_service",
                            resource_id=res_id,
                            data_category="USER_EXPORT",
                            observed_state="PRESENT",
                            subject_id=subj_id,
                            subject_email=email,
                            subject_phone=phone,
                            observation_time=updated_at,
                            captured_at=captured_at,
                            extraction_method="SQL_EXEC",
                            details={"table": "customer_exports", "raw": r},
                        )
                    )

            # 6. connector_subscriptions
            if "connector_subscriptions" in tables:
                cursor.execute("SELECT * FROM connector_subscriptions;")
                col_names = [d[0] for d in cursor.description]
                for row in cursor.fetchall():
                    r = dict(zip(col_names, row))
                    res_id = r.get("resource_id") or ""
                    subj_id = r.get("customer_reference")
                    email = (r.get("customer_email") or "").lower() or None
                    enabled = bool(r.get("enabled"))
                    updated_at = parse_iso8601(r["updated_at"]) if "updated_at" in r and r["updated_at"] else None
                    state = "ACTIVE" if enabled else "DISABLED"
                    observations.append(
                        ExtractedObservation(
                            file_id=file_id,
                            source_path=str(file_path),
                            system_id="integration_service",
                            resource_id=res_id,
                            data_category=None,
                            observed_state=state,
                            subject_id=subj_id,
                            subject_email=email,
                            subject_phone=None,
                            observation_time=updated_at,
                            captured_at=captured_at,
                            extraction_method="SQL_EXEC",
                            details={"table": "connector_subscriptions", "enabled": enabled, "raw": r},
                        )
                    )

            # 7. backup_restore_entries
            if "backup_restore_entries" in tables:
                cursor.execute("SELECT * FROM backup_restore_entries;")
                col_names = [d[0] for d in cursor.description]
                for row in cursor.fetchall():
                    r = dict(zip(col_names, row))
                    res_id = r.get("resource_id") or ""
                    subj_id = r.get("customer_reference")
                    email = (r.get("customer_email") or "").lower() or None
                    restore_allowed = bool(r.get("restore_allowed"))
                    updated_at = parse_iso8601(r["updated_at"]) if "updated_at" in r and r["updated_at"] else None
                    state = "ACTIVE" if restore_allowed else "BLOCKED"
                    observations.append(
                        ExtractedObservation(
                            file_id=file_id,
                            source_path=str(file_path),
                            system_id="backup_service",
                            resource_id=res_id,
                            data_category="BACKUP_ARCHIVE",
                            observed_state=state,
                            subject_id=subj_id,
                            subject_email=email,
                            subject_phone=None,
                            observation_time=updated_at,
                            captured_at=captured_at,
                            extraction_method="SQL_EXEC",
                            details={"table": "backup_restore_entries", "restore_allowed": restore_allowed, "can_be_blocked": True, "raw": r},
                        )
                    )

            # 8. security_audit_records
            if "security_audit_records" in tables:
                cursor.execute("SELECT * FROM security_audit_records;")
                col_names = [d[0] for d in cursor.description]
                for row in cursor.fetchall():
                    r = dict(zip(col_names, row))
                    res_id = r.get("resource_id") or ""
                    subj_id = r.get("subject_reference")
                    retention_until = parse_iso8601(r["retention_until"]) if "retention_until" in r and r["retention_until"] else None
                    updated_at = parse_iso8601(r["updated_at"]) if "updated_at" in r and r["updated_at"] else None
                    observations.append(
                        ExtractedObservation(
                            file_id=file_id,
                            source_path=str(file_path),
                            system_id="security_service",
                            resource_id=res_id,
                            data_category="SECURITY_AUDIT_LOG",
                            observed_state="PRESENT",
                            subject_id=subj_id,
                            subject_email=None,
                            subject_phone=None,
                            observation_time=updated_at,
                            captured_at=captured_at,
                            extraction_method="SQL_EXEC",
                            details={"table": "security_audit_records", "retention_until": retention_until, "raw": r},
                        )
                    )

            # 9. Generic replica tables with JSON records
            generic_tables = [
                "customer_data_primary", "customer_data_read_replica",
                "customer_data_failover", "customer_data_failover_replica",
                "customer_data_reporting_replica", "customer_data_replica_ap_south",
                "customer_data_replica_eu_west"
            ]
            for gt in generic_tables:
                if gt in tables:
                    cursor.execute(f"SELECT resource_id, origin_system, collection_name, record_json, updated_at FROM \"{gt}\";")
                    for row in cursor.fetchall():
                        res_id, orig_sys, coll_name, rec_json_str, upd_str = row
                        upd_time = parse_iso8601(upd_str) if upd_str else None
                        try:
                            rec = json.loads(rec_json_str) if rec_json_str else {}
                        except Exception:
                            rec = {}

                        doc = rec.get("document") if isinstance(rec.get("document"), dict) else rec
                        subj_id = rec.get("customer_reference") or rec.get("user_id") or rec.get("subject_reference") or doc.get("customer_reference") or doc.get("user_id") or doc.get("subject_reference")
                        email = (rec.get("email") or rec.get("requester_email") or rec.get("customer_email") or rec.get("owner_email") or doc.get("email") or doc.get("requester_email") or doc.get("customer_email") or doc.get("owner_email") or "").lower() or None
                        phone = rec.get("phone") or rec.get("requester_phone") or rec.get("owner_phone") or doc.get("phone") or doc.get("requester_phone") or doc.get("owner_phone")

                        # Determine system and category
                        sys_id = orig_sys or "account_service"
                        cat = None
                        state = "PRESENT"

                        if coll_name == "customer_profiles":
                            cat = "USER_PROFILE"
                            status = rec.get("account_status")
                            state = "ABSENT" if status == "DELETED" else "PRESENT"
                        elif coll_name == "profile_lookups":
                            cat = "USER_PROFILE"
                            prof = rec.get("profile")
                            if rec.get("status_code") == 404 or prof is None or (isinstance(prof, dict) and prof.get("account_status") == "DELETED"):
                                state = "ABSENT"
                            else:
                                state = "PRESENT"
                        elif coll_name in ("customer_search_documents", "search_index"):
                            cat = "SEARCH_INDEX_ENTRY"
                            state = "PRESENT"
                        elif coll_name in ("customer_analytics_profiles", "customer_analytics_reports"):
                            cat = "ANALYTICS_PROFILE"
                            is_attr = bool(subj_id or email or phone)
                            state = "PRESENT" if is_attr else "ANONYMIZED"
                        elif coll_name in ("support_records", "tickets"):
                            cat = "SUPPORT_MESSAGE"
                            state = "PRESENT"
                        elif coll_name in ("customer_exports", "export_jobs"):
                            cat = "USER_EXPORT"
                            state = "PRESENT"
                        elif coll_name in ("connector_subscriptions", "connectors"):
                            sys_id = "integration_service"
                            enabled = bool(rec.get("enabled"))
                            state = "ACTIVE" if enabled else "DISABLED"
                        elif coll_name in ("backup_restore_entries", "backup_catalog"):
                            sys_id = "backup_service"
                            cat = "BACKUP_ARCHIVE"
                            restore_allowed = bool(rec.get("restore_allowed"))
                            state = "ACTIVE" if restore_allowed else "BLOCKED"
                        elif coll_name in ("security_audit_records", "audit_events"):
                            sys_id = "security_service"
                            cat = "SECURITY_AUDIT_LOG"
                            state = "PRESENT"

                        observations.append(
                            ExtractedObservation(
                                file_id=file_id,
                                source_path=str(file_path),
                                system_id=sys_id,
                                resource_id=res_id,
                                data_category=cat,
                                observed_state=state,
                                subject_id=subj_id,
                                subject_email=email,
                                subject_phone=phone,
                                observation_time=upd_time,
                                captured_at=captured_at,
                                extraction_method="SQL_EXEC",
                                details={"table": gt, "collection": coll_name, "raw": rec},
                            )
                        )

        except Exception as e:
            # Record uncertainty or failure
            observations.append(
                ExtractedObservation(
                    file_id=file_id,
                    source_path=str(file_path),
                    system_id="unknown",
                    resource_id=f"error_{file_id}",
                    observed_state="UNKNOWN",
                    captured_at=captured_at,
                    extraction_method="SQL_EXEC",
                    uncertainty=f"Failed to execute SQL: {e}",
                )
            )
        finally:
            conn.close()

        return observations
