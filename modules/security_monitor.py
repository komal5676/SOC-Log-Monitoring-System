
# modules/security_monitor.py

import socket
import xml.etree.ElementTree as ET
from datetime import datetime

from modules.event_reader import read_windows_events
from modules.threat_detection import detect_threat
from modules.correlation_engine import correlate_events
from modules.risk_engine import calculate_risk
from modules.alerting import check_and_alert
from modules.logger import get_logger


logger = get_logger("security_monitor")
HOSTNAME = socket.gethostname()


# ============================================================
# EVENT FIELD CONFIGURATION
# ============================================================

# These are fallback indexes for classic Windows event records.
# Named XML event fields are preferred whenever they are available.
USERNAME_INDEX_BY_EVENT = {
    4624: (5, 1),
    4625: (5, 1),
    4672: (1,),
    4688: (1,),
    4720: (4, 1),
    4728: (4, 6, 1),
    4799: (1, 5),
}

LOGON_ID_INDEX_BY_EVENT = {
    4624: (3,),
    4625: (3,),
    4672: (3,),
    4688: (3,),
    4720: (3,),
    4728: (3,),
    4799: (3,),
}


# ============================================================
# GENERAL HELPERS
# ============================================================

def _clean_value(value):
    """Convert a field into a clean string or return Unknown."""
    if value is None:
        return "Unknown"

    value = str(value).strip()

    if not value:
        return "Unknown"

    if value.lower() in {
        "-", "n/a", "none", "null", "unknown"
    }:
        return "Unknown"

    return value


def _get_string_inserts(event):
    """Safely retrieve classic Windows event insertion strings."""
    inserts = getattr(event, "StringInserts", None)

    if not inserts:
        return []

    try:
        return list(inserts)
    except (TypeError, ValueError):
        return []


def _get_named_event_data(event):
    """
    Extract named EventData fields if this event object exposes XML.

    Classic win32evtlog.ReadEventLog records often do not expose XML.
    In that case, the extraction functions use StringInserts instead.
    """
    xml_text = getattr(event, "Xml", None)

    if not xml_text:
        return {}

    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, TypeError, ValueError):
        return {}

    result = {}

    for element in root.iter():
        if element.tag.endswith("Data"):
            name = element.attrib.get("Name")
            if name:
                result[name] = _clean_value(element.text)

    return result


def _get_named_value(data, *field_names):
    """Return the first usable value among named XML fields."""
    for field_name in field_names:
        value = _clean_value(data.get(field_name))

        if value != "Unknown":
            return value

    return "Unknown"


def _get_indexed_value(inserts, indexes):
    """Return the first usable value from configured fallback indexes."""
    for index in indexes:
        if 0 <= index < len(inserts):
            value = _clean_value(inserts[index])

            if value != "Unknown":
                return value

    return "Unknown"


def _is_logon_id(value):
    """Recognize common Windows hexadecimal Logon IDs."""
    value = _clean_value(value)

    if value == "Unknown":
        return False

    if value.lower().startswith("0x"):
        try:
            int(value[2:], 16)
            return True
        except ValueError:
            return False

    return False


# ============================================================
# USERNAME EXTRACTION
# ============================================================

def _extract_username(event, event_id):
    """
    Extract the relevant account name for supported Windows events.

    Preference:
    1. Named XML fields, if available.
    2. Event-specific classic StringInserts indexes.
    """
    data = _get_named_event_data(event)

    named_fields = {
        4624: ("TargetUserName", "SubjectUserName"),
        4625: ("TargetUserName", "SubjectUserName"),
        4672: ("SubjectUserName",),
        4688: ("SubjectUserName", "TargetUserName"),
        4720: ("TargetUserName", "NewAccountName",
              "SubjectUserName"),
        4728: ("MemberName", "TargetUserName",
              "SubjectUserName"),
        4799: ("SubjectUserName", "TargetUserName"),
    }

    username = _get_named_value(
        data,
        *named_fields.get(event_id, (
            "TargetUserName",
            "SubjectUserName",
            "MemberName",
            "NewAccountName",
        ))
    )

    if username != "Unknown":
        return username

    inserts = _get_string_inserts(event)
    indexes = USERNAME_INDEX_BY_EVENT.get(event_id, ())

    return _get_indexed_value(inserts, indexes)


# ============================================================
# LOGON ID EXTRACTION
# ============================================================

def _extract_logon_id(event, event_id):
    """
    Extract the relevant Logon ID.

    Successful logon (4624) uses TargetLogonId.
    Failed logon (4625), privilege assignment (4672),
    process creation (4688), and group enumeration (4799)
    normally use SubjectLogonId.
    """
    data = _get_named_event_data(event)

    named_fields = {
        4624: ("TargetLogonId",),
        4625: ("SubjectLogonId",),
        4672: ("SubjectLogonId",),
        4688: ("SubjectLogonId",),
        4720: ("SubjectLogonId",),
        4728: ("SubjectLogonId",),
        4799: ("SubjectLogonId",),
    }

    logon_id = _get_named_value(
        data,
        *named_fields.get(event_id, ())
    )

    if _is_logon_id(logon_id):
        return logon_id

    inserts = _get_string_inserts(event)
    indexes = LOGON_ID_INDEX_BY_EVENT.get(event_id, ())

    # Prefer the event-specific Logon ID field.
    logon_id = _get_indexed_value(inserts, indexes)

    if _is_logon_id(logon_id):
        return logon_id

    # Some event versions vary in their insertion-string layout.
    # Scan for a hexadecimal value only as a last resort.
    # This is best-effort and may be ambiguous for some events.
    for value in inserts:
        value = _clean_value(value)

        if _is_logon_id(value):
            return value

    return "Unknown"


# ============================================================
# EVENT TIME
# ============================================================

def _extract_event_time(event):
    """Return a timestamp suitable for the dashboard and correlation."""
    time_value = getattr(event, "TimeGenerated", None)

    if time_value is None:
        return datetime.now().isoformat(timespec="seconds")

    if isinstance(time_value, datetime):
        return time_value.isoformat(sep=" ", timespec="seconds")

    return str(time_value)


# ============================================================
# COLLECT WINDOWS SECURITY EVENTS
# ============================================================

def get_security_events():
    """
    Read Windows Security events and convert them to dictionaries.

    The output keys are kept compatible with the existing dashboard.
    """
    windows_events = read_windows_events()
    detected_events = []

    for event in windows_events:
        try:
            event_id = int(event.EventID) & 0xFFFF
        except (AttributeError, TypeError, ValueError):
            logger.warning("Skipping an event with an invalid Event ID.")
            continue

        try:
            threat = detect_threat(event_id) or {}
        except Exception:
            logger.exception(
                "Threat classification failed for Event ID %s",
                event_id,
            )
            threat = {}

        # Keep events even when no threat rule matches them.
        if threat.get("name") == "Unknown Event" or not threat:
            threat = {
                "name": "Windows Event",
                "severity": "Info",
                "icon": "ℹ️",
                "category": "System Activity",
                "description": f"Windows Security Event {event_id}",
                "mitre_id": None,
                "mitre_tactic": None,
            }

        username = _extract_username(event, event_id)
        logon_id = _extract_logon_id(event, event_id)

        detected_events.append({
            "record_id": getattr(event, "RecordNumber", None),
            "event_id": event_id,
            "name": threat.get("name", "Windows Event"),
            "severity": threat.get("severity", "Info"),
            "icon": threat.get("icon", "ℹ️"),
            "category": threat.get("category", "System Activity"),
            "description": threat.get(
                "description",
                f"Windows Security Event {event_id}",
            ),
            "mitre_id": threat.get("mitre_id"),
            "mitre_tactic": threat.get("mitre_tactic"),
            "source": getattr(event, "SourceName", "Windows"),
            "hostname": HOSTNAME,
            "user": username,
            "logon_id": logon_id,
            "time": _extract_event_time(event),
        })

    return detected_events


# ============================================================
# SECURITY SUMMARY
# ============================================================

def get_security_summary():
    """Return the existing event and incident risk summary structure."""
    events = get_security_events()
    incidents = correlate_events(events)
    return calculate_risk(events, incidents)
