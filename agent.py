from dotenv import load_dotenv
load_dotenv()
import hashlib
import json
import os
import re
import socket
import sqlite3
import time

import requests

from modules.event_reader import read_windows_events
from modules.threat_detection import detect_threat


# ============================================================
# CONFIGURATION
# ============================================================

CENTRAL_SERVER_URL = "http://127.0.0.1:5000/ingest"
import os

POLL_INTERVAL_SECONDS = 30
API_KEY = os.environ.get("API_KEY")

MAX_SEND_RETRIES = 3
RETRY_BACKOFF_SECONDS = 5
MAX_EVENTS_PER_REQUEST = 100
REQUEST_TIMEOUT_SECONDS = 30

HOSTNAME = socket.gethostname()
AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
QUEUE_DB_PATH = os.path.join(AGENT_DIR, "agent_queue.db")

def send_heartbeat():
    """Send endpoint heartbeat to the central SOC server."""
    heartbeat_url = (
        CENTRAL_SERVER_URL.rsplit("/", 1)[0] + "/heartbeat"
    )

    try:
        response = requests.post(
            heartbeat_url,
            json={"hostname": HOSTNAME},
            headers={"X-API-Key": API_KEY},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        print(f"[HEARTBEAT] Sent successfully for {HOSTNAME}")
        return True

    except requests.RequestException as exc:
        print(f"[HEARTBEAT] Failed: {exc}")
        return False



# ============================================================
# PERSISTENT QUEUE
# ============================================================

def get_queue_connection():
    conn = sqlite3.connect(QUEUE_DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_queue_db():
    conn = get_queue_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pending_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_key TEXT NOT NULL UNIQUE,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS seen_events (
                event_key TEXT PRIMARY KEY,
                first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
    finally:
        conn.close()



def make_event_key(event):
    record_id = event.get("record_id")

    if record_id is not None:
        raw_key = f"{HOSTNAME}|record|{record_id}"
    else:
        fields = (
            HOSTNAME,
            event.get("event_id"),
            event.get("time"),
            event.get("source"),
            event.get("user"),
            event.get("description"),
        )
        raw_key = "|".join(str(value or "") for value in fields)

    return hashlib.sha256(
        raw_key.encode("utf-8", errors="replace")
    ).hexdigest()

def enqueue_new_events(events):
    if not events:
        return 0

    conn = get_queue_connection()
    added = 0

    try:
        with conn:
            for event in events:
                key = make_event_key(event)
                event_json = json.dumps(
                    event,
                    ensure_ascii=False
                )

                cursor = conn.execute("""
                    INSERT OR IGNORE INTO seen_events (event_key)
                    VALUES (?)
                """, (key,))

                if cursor.rowcount == 1:
                    conn.execute("""
                        INSERT OR IGNORE INTO pending_events
                            (event_key, payload_json)
                        VALUES (?, ?)
                    """, (key, event_json))
                    added += 1
    finally:
        conn.close()

    return added


def get_pending_batch(limit=MAX_EVENTS_PER_REQUEST):
    conn = get_queue_connection()
    try:
        rows = conn.execute("""
            SELECT id, event_key, payload_json
            FROM pending_events
            ORDER BY id ASC
            LIMIT ?
        """, (limit,)).fetchall()

        batch = []

        for row in rows:
            try:
                event = json.loads(row["payload_json"])
            except (TypeError, json.JSONDecodeError):
                print(
                    f"Invalid JSON in queue row {row['id']}; "
                    "leaving it in the queue."
                )
                continue

            batch.append({
                "queue_id": row["id"],
                "event_key": row["event_key"],
                "event": event,
            })

        return batch
    finally:
        conn.close()


def acknowledge_batch(batch):
    if not batch:
        return

    conn = get_queue_connection()
    try:
        with conn:
            conn.executemany(
                "DELETE FROM pending_events WHERE id = ?",
                [(item["queue_id"],) for item in batch]
            )
    finally:
        conn.close()


def pending_count():
    conn = get_queue_connection()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS total FROM pending_events"
        ).fetchone()
        return row["total"] if row else 0
    finally:
        conn.close()


# ============================================================
# EVENT DETAILS
# ============================================================

USERNAME_INDEX_BY_EVENT = {
    4624: 5,
    4625: 5,
    4672: 1,
    4720: 0,
    4728: 2,
}


def _extract_username(event, event_id):
    inserts = getattr(event, "StringInserts", None)

    if not inserts:
        return "Unknown"

    index = USERNAME_INDEX_BY_EVENT.get(event_id)

    if index is None or index >= len(inserts):
        return "Unknown"

    value = inserts[index]

    if value is None:
        return "Unknown"

    value = str(value).strip()
    return value if value else "Unknown"


def _extract_logon_id(event, event_id):
    if event_id not in (4624, 4625, 4672):
        return "Unknown"

    inserts = getattr(event, "StringInserts", None)

    if not inserts:
        return "Unknown"

    for value in inserts:
        if value is None:
            continue

        value = str(value).strip()

        if re.fullmatch(r"0x[0-9a-fA-F]+", value):
            return value

    return "Unknown"


# ============================================================
# COLLECT WINDOWS EVENTS
# ============================================================

def collect_events():
    windows_events = read_windows_events()
    detected = []

    for event in windows_events:
        event_id = event.EventID & 0xFFFF
        threat = detect_threat(event_id)

        if threat.get("name") == "Unknown Event":
            threat = {
                "name": "Windows Event",
                "severity": "Info",
                "category": "System Activity",
                "description": f"Windows Security Event {event_id}",
                "mitre_id": None,
                "mitre_tactic": None,
            }

        detected.append({
            "record_id": getattr(event, "RecordNumber", None),
            "event_id": event_id,
            "name": threat.get("name", "Windows Event"),
            "severity": threat.get("severity", "Info"),
            "category": threat.get("category", "System Activity"),
            "description": threat.get(
                "description", "Windows security event"
            ),
            "mitre_id": threat.get("mitre_id"),
            "mitre_tactic": threat.get("mitre_tactic"),
            "source": getattr(event, "SourceName", "Windows"),
            "user": _extract_username(event, event_id),
            "logon_id": _extract_logon_id(event, event_id),
            "time": str(event.TimeGenerated),
        })

    print(
        f"[{HOSTNAME}] Events read: {len(windows_events)}; "
        f"events prepared: {len(detected)}"
    )
    return detected


# ============================================================
# SEND QUEUED EVENTS
# ============================================================

def deliver_pending_events():
    while True:
        batch = get_pending_batch()

        if not batch:
            return True

        payload = {
            "hostname": HOSTNAME,
            "events": [item["event"] for item in batch],
        }
        headers = {"X-API-Key": API_KEY}
        accepted = False

        for attempt in range(1, MAX_SEND_RETRIES + 1):
            try:
                response = requests.post(
                    CENTRAL_SERVER_URL,
                    json=payload,
                    headers=headers,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )

                if response.status_code == 200:
                    acknowledge_batch(batch)
                    print(
                        f"[{HOSTNAME}] Accepted {len(batch)} events. "
                        f"Queue remaining: {pending_count()}"
                    )
                    accepted = True
                    break

                print(
                    f"Server returned {response.status_code}: "
                    f"{response.text[:200]}"
                )

                if response.status_code == 401:
                    print("Check the agent API_KEY.")
                    return False

                # Do not retry a request rejected as invalid.
                if 400 <= response.status_code < 500:
                    return False

            except requests.exceptions.RequestException as exc:
                print(
                    f"Delivery attempt {attempt}/"
                    f"{MAX_SEND_RETRIES} failed: {exc}"
                )

            if attempt < MAX_SEND_RETRIES:
                time.sleep(RETRY_BACKOFF_SECONDS * attempt)

        if not accepted:
            print(
                f"Delivery failed. {pending_count()} events "
                "remain saved for retry."
            )
            return False


# ============================================================
# MAIN LOOP
# ============================================================

def run():
    init_queue_db()

    print(f"SentinelX agent started on {HOSTNAME}")
    print(f"Queue database: {QUEUE_DB_PATH}")
    
    print(f"Pending events: {pending_count()}")

    last_heartbeat = 0.0

    while True:
        try:
            # Send heartbeat every 30 seconds
            if time.monotonic() - last_heartbeat >= 30:
                send_heartbeat()
                last_heartbeat = time.monotonic()

            events = collect_events()
            added = enqueue_new_events(events)

            if added:
                print(f"New events saved to queue: {added}")

            # Retry pending events even when no new events were collected.
            deliver_pending_events()

        except KeyboardInterrupt:
            print("\nAgent stopped. Pending events remain saved.")
            break

        except Exception as exc:
            print(
                f"Agent cycle error: {type(exc).__name__}: {exc}"
            )

        print(f"Queue size: {pending_count()}")
        time.sleep(POLL_INTERVAL_SECONDS)



if __name__ == "__main__":
    run()
