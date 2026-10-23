import os
import sqlite3

from modules.logger import get_logger


logger = get_logger("database")


# ============================================================
# DATABASE PATH
# ============================================================

PROJECT_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DB_PATH = os.path.join(
    PROJECT_DIR,
    "database.db"
)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row

    return conn


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():

    conn = get_connection()
    cursor = conn.cursor()

    # --------------------------------------------------------
    # Legacy logs table
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_message TEXT NOT NULL
        )
    """)

    # --------------------------------------------------------
    # Security events table
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            record_id INTEGER,
            event_id INTEGER,
            name TEXT,
            severity TEXT,
            category TEXT,
            description TEXT,
            mitre_id TEXT,
            mitre_tactic TEXT,
            source TEXT,
            user TEXT,
            logon_id TEXT,
            time TEXT NOT NULL,
            received_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # --------------------------------------------------------
    # Check existing columns
    # --------------------------------------------------------

    cursor.execute("""
        PRAGMA table_info(events)
    """)

    columns = [
        row["name"]
        for row in cursor.fetchall()
    ]

    # --------------------------------------------------------
    # Add record_id if old database is being used
    # --------------------------------------------------------

    if "record_id" not in columns:

        cursor.execute("""
            ALTER TABLE events
            ADD COLUMN record_id INTEGER
        """)

        logger.info(
            "Added record_id column to events table."
        )

    # --------------------------------------------------------
    # Add logon_id if old database is being used
    # --------------------------------------------------------

    if "logon_id" not in columns:

        cursor.execute("""
            ALTER TABLE events
            ADD COLUMN logon_id TEXT
        """)

        logger.info(
            "Added logon_id column to events table."
        )

    # --------------------------------------------------------
    # Prevent duplicate Windows events
    #
    # Keep this protection. It prevents the same Windows
    # record from being stored repeatedly.
    # --------------------------------------------------------

    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_unique_host_record
        ON events(hostname, record_id)
        WHERE record_id IS NOT NULL
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_hostname_id ON events(hostname, id DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(time)")
    # Endpoint heartbeat tracking
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS endpoint_status (
            hostname TEXT PRIMARY KEY,
            last_seen TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

    logger.info(
        "Database initialized successfully."
    )
# ============================================================
# ENDPOINT HEARTBEAT FUNCTIONS
# ============================================================

def record_heartbeat(hostname):
    """Save the latest heartbeat received from an endpoint."""

    from datetime import datetime, timezone

    hostname = (hostname or "").strip()

    if not hostname:
        return False

    conn = get_connection()

    try:
        conn.execute("""
            INSERT INTO endpoint_status (hostname, last_seen)
            VALUES (?, ?)
            ON CONFLICT(hostname)
            DO UPDATE SET last_seen = excluded.last_seen
        """, (
            hostname,
            datetime.now(timezone.utc).isoformat()
        ))

        conn.commit()
        return True

    finally:
        conn.close()


def list_endpoints():
    """Return registered endpoints and their stored event counts."""

    conn = get_connection()

    try:
        rows = conn.execute("""
            SELECT
                h.hostname,
                s.last_seen,
                (
                    SELECT COUNT(*)
                    FROM events e
                    WHERE e.hostname = h.hostname
                ) AS event_count
            FROM (
                SELECT hostname FROM events
                UNION
                SELECT hostname FROM endpoint_status
            ) h
            LEFT JOIN endpoint_status s
                ON s.hostname = h.hostname
            ORDER BY h.hostname
        """).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()

# ============================================================
# LEGACY LOG FUNCTIONS
# ============================================================

def read_logs():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT log_message
        FROM logs
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return [
        row["log_message"]
        for row in rows
    ]


def insert_log(message):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO logs (log_message)
        VALUES (?)
    """, (message,))

    conn.commit()
    conn.close()


# ============================================================
# INSERT ONE SECURITY EVENT
# ============================================================

def insert_event(hostname, event):

    conn = None

    try:

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT OR IGNORE INTO events
            (
                hostname,
                record_id,
                event_id,
                name,
                severity,
                category,
                description,
                mitre_id,
                mitre_tactic,
                source,
                user,
                logon_id,
                time
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            hostname,
            event.get("record_id"),
            event.get("event_id"),
            event.get("name"),
            event.get("severity"),
            event.get("category"),
            event.get("description"),
            event.get("mitre_id"),
            event.get("mitre_tactic"),
            event.get("source"),
            event.get("user", "Unknown"),
            event.get("logon_id", "Unknown"),
            event.get("time")
        ))

        inserted = cursor.rowcount

        conn.commit()

        return inserted == 1

    except sqlite3.Error as e:

        logger.error(
            "Failed to insert event from %s: %s",
            hostname,
            e
        )

        return False

    finally:

        if conn:
            conn.close()


# ============================================================
# INSERT MULTIPLE EVENTS
# ============================================================

def insert_events(hostname, events):

    inserted_count = 0

    conn = None

    try:

        conn = get_connection()
        cursor = conn.cursor()

        for event in events:

            cursor.execute("""
                INSERT OR IGNORE INTO events
                (
                    hostname,
                    record_id,
                    event_id,
                    name,
                    severity,
                    category,
                    description,
                    mitre_id,
                    mitre_tactic,
                    source,
                    user,
                    logon_id,
                    time
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                hostname,
                event.get("record_id"),
                event.get("event_id"),
                event.get("name"),
                event.get("severity"),
                event.get("category"),
                event.get("description"),
                event.get("mitre_id"),
                event.get("mitre_tactic"),
                event.get("source"),
                event.get("user", "Unknown"),
                event.get("logon_id", "Unknown"),
                event.get("time")
            ))

            if cursor.rowcount == 1:
                inserted_count += 1

        conn.commit()

        logger.info(
            "Stored %d new events from %s.",
            inserted_count,
            hostname
        )

        return inserted_count

    except sqlite3.Error as e:

        if conn:
            conn.rollback()

        logger.error(
            "Failed to insert events from %s: %s",
            hostname,
            e
        )

        return inserted_count

    finally:

        if conn:
            conn.close()


# ============================================================
# READ EVENTS
# ============================================================

def read_events(hostname=None, limit=5000, offset=0):
    """Read one page of events, newest first. limit/offset are parameterized."""
    limit = max(1, int(limit))
    offset = max(0, int(offset))
    conn = get_connection()
    try:
        cursor = conn.cursor()
        if hostname:
            cursor.execute("""
                SELECT * FROM events
                WHERE hostname = ?
                ORDER BY id DESC
                LIMIT ? OFFSET ?
            """, (hostname, limit, offset))
        else:
            cursor.execute("""
                SELECT * FROM events
                ORDER BY id DESC
                LIMIT ? OFFSET ?
            """, (limit, offset))
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


# ============================================================
# TOTAL EVENT COUNT
# ============================================================

def count_events(hostname=None):

    conn = get_connection()
    cursor = conn.cursor()

    if hostname:

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM events
            WHERE hostname = ?
        """, (
            hostname,
        ))

    else:

        cursor.execute("""
            SELECT COUNT(*) AS total
            FROM events
        """)

    row = cursor.fetchone()

    conn.close()

    return row["total"] if row else 0


# ============================================================
# FULL-DATABASE EVENT SEARCH
# ============================================================

_SEARCH_COLUMNS = (
    "record_id", "event_id", "hostname", "user", "name", "severity",
    "category", "description", "mitre_id", "mitre_tactic", "source",
    "logon_id", "time", "received_at"
)



def _search_where(
    keyword="",
    hostname=None,
    event_id=None,
    severity=None,
    username=None,
    start_time=None,
    end_time=None,
):
    clauses = []
    params = []

    if hostname:
        clauses.append("hostname = ?")
        params.append(hostname)

    if event_id:
        clauses.append("CAST(event_id AS TEXT) = ?")
        params.append(str(event_id))

    if severity:
        clauses.append("severity = ?")
        params.append(severity)

    if username:
        clauses.append("COALESCE(user, '') LIKE ? COLLATE NOCASE")
        params.append(f"%{username}%")

    if start_time:
        clauses.append("time >= ?")
        params.append(start_time.replace("T", " "))

    if end_time:
        clauses.append("time <= ?")
        params.append(end_time.replace("T", " "))

    keyword = (keyword or "").strip()

    if keyword:
        escaped = (
            keyword.replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        like_value = f"%{escaped}%"

        clauses.append(
            "(" + " OR ".join(
                f"CAST(COALESCE({column}, '') AS TEXT) "
                "LIKE ? ESCAPE '\\' COLLATE NOCASE"
                for column in _SEARCH_COLUMNS
            ) + ")"
        )
        params.extend([like_value] * len(_SEARCH_COLUMNS))

    where_sql = (
        " WHERE " + " AND ".join(clauses)
        if clauses else ""
    )

    return where_sql, params


def search_events(
    keyword="",
    hostname=None,
    limit=50,
    offset=0,
    event_id=None,
    severity=None,
    username=None,
    start_time=None,
    end_time=None,
):
    """Search stored events using filters and return one page."""
    limit = max(1, int(limit))
    offset = max(0, int(offset))

    where_sql, params = _search_where(
        keyword,
        hostname,
        event_id,
        severity,
        username,
        start_time,
        end_time,
    )

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT * FROM events{where_sql} "
            "ORDER BY id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        )
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def count_search_events(
    keyword="",
    hostname=None,
    event_id=None,
    severity=None,
    username=None,
    start_time=None,
    end_time=None,
):
    """Count all filtered events for accurate pagination."""
    where_sql, params = _search_where(
        keyword,
        hostname,
        event_id,
        severity,
        username,
        start_time,
        end_time,
    )

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT COUNT(*) AS total FROM events{where_sql}",
            params,
        )
        row = cursor.fetchone()
        return row["total"] if row else 0
    finally:
        conn.close()

# ============================================================
# HOSTNAMES
# ============================================================

def list_hostnames():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT DISTINCT hostname
        FROM events
        ORDER BY hostname
    """)

    rows = cursor.fetchall()

    conn.close()

    return [
        row["hostname"]
        for row in rows
    ]


# ============================================================
# DAILY SEVERITY COUNTS
# ============================================================

def daily_severity_counts(days=14):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            date(received_at) AS day,
            severity,
            COUNT(*) AS count
        FROM events
        WHERE received_at >= datetime('now', ?)
        GROUP BY day, severity
        ORDER BY day ASC
    """, (
        f"-{days} days",
    ))

    rows = cursor.fetchall()

    conn.close()

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# TOP MITRE TECHNIQUES
# ============================================================

def top_mitre_techniques(limit=10):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            mitre_id,
            mitre_tactic,
            COUNT(*) AS count
        FROM events
        WHERE mitre_id IS NOT NULL
        GROUP BY mitre_id, mitre_tactic
        ORDER BY count DESC
        LIMIT ?
    """, (
        limit,
    ))

    rows = cursor.fetchall()

    conn.close()

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# INITIALIZE DATABASE
# ============================================================

init_db()
