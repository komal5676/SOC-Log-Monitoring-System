
# ============================================================
# SENTINELX - PERSISTENT ALERT HISTORY
# ============================================================

import hashlib
import json

from modules.database import get_connection


def _incident_fingerprint(incident):
    """
    Create a stable fingerprint for an incident's current evidence.
    The same incident with the same event records gets the same
    fingerprint, including after a Flask restart.
    """

    event_keys = []

    for event in incident.get("events", []):
        record_id = event.get("record_id")

        if record_id is None:
            record_id = event.get("id")

        if record_id is not None:
            event_key = {
                "record_id": str(record_id),
                "event_id": event.get("event_id"),
            }
        else:
            event_key = {
                "event_id": event.get("event_id"),
                "time": event.get("time") or event.get("timestamp"),
                "user": event.get("user"),
            }

        event_keys.append(event_key)

    event_keys.sort(
        key=lambda item: json.dumps(item, sort_keys=True)
    )

    identity = {
        "type": incident.get("type", ""),
        "name": incident.get("name", ""),
        "hostname": str(
            incident.get("hostname")
            or incident.get("host")
            or ""
        ).strip().lower(),
        "user": str(
            incident.get("user") or ""
        ).strip().lower(),
        "events": event_keys,
    }

    canonical = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def claim_new_alerts(incidents, risk_threshold):
    """
    Return incidents that have not previously been alerted.

    The SQLite primary key prevents duplicate claims, even if
    multiple ingestion requests process the same incident.
    """

    connection = get_connection()
    new_alerts = []

    try:
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alert_history (
                fingerprint TEXT PRIMARY KEY,
                incident_name TEXT,
                hostname TEXT,
                username TEXT,
                risk_score REAL,
                first_alerted_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        for incident in incidents:
            if not isinstance(incident, dict):
                continue

            try:
                risk_score = float(
                    incident.get("risk_score", 0)
                )
            except (TypeError, ValueError):
                continue

            if risk_score < risk_threshold:
                continue

            fingerprint = _incident_fingerprint(incident)

            cursor.execute("""
                INSERT OR IGNORE INTO alert_history (
                    fingerprint,
                    incident_name,
                    hostname,
                    username,
                    risk_score
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                fingerprint,
                str(incident.get("name", "Unknown Incident")),
                str(
                    incident.get("hostname")
                    or incident.get("host")
                    or "unknown host"
                ),
                str(incident.get("user", "Unknown")),
                risk_score,
            ))

            if cursor.rowcount == 1:
                new_alerts.append(incident)

        connection.commit()
        return new_alerts

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

