
# ============================================================
# SENTINELX - EVENT CORRELATION ENGINE
# ============================================================

from datetime import datetime, timedelta, timezone


# ============================================================
# CORRELATION SETTINGS
# ============================================================

CORRELATION_WINDOW_MINUTES = 5
FREQUENCY_WINDOW_MINUTES = 10
FREQUENCY_THRESHOLD = 3

# Events that should not trigger frequency incidents
# solely because they occur repeatedly.
FREQUENCY_EXCLUDED_EVENT_IDS = {
    4624,  # Successful logins are common Windows activity
    4799,  # Group membership enumeration can be legitimate
    5379,  # Credential Manager access can be routine
}


SEVERITY_ORDER = {
    "Info": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}

SEVERITY_SCORES = {
    "Critical": 90,
    "High": 70,
    "Medium": 40,
    "Low": 10,
    "Info": 0,
}


# ============================================================
# ATTACK PATTERNS
# ============================================================

ATTACK_PATTERNS = [
    {
        "name": "Brute Force → Successful Login",
        "sequence": [4625, 4624],
        "min_repeats": {4625: 3},
        "severity": "High",
        "description": (
            "Multiple failed logins followed by a successful "
            "login were observed. Investigate whether the "
            "successful login is related to the failed attempts."
        ),
    },
    {
        "name": "Login → Privilege Escalation",
        "sequence": [4624, 4672],
        "min_repeats": {},
        "severity": "Medium",
        "description": (
            "A successful login and a special-privileges event "
            "were observed in the same known Windows logon "
            "session. This may be normal administrative activity."
        ),
        "require_same_logon_id": True,
    },
    {
        "name": "Privilege Escalation → Account Creation",
        "sequence": [4672, 4720],
        "min_repeats": {},
        "severity": "Critical",
        "description": (
            "A special-privileges event and a user-account "
            "creation event were observed close together. "
            "Verify the account creator and the new account."
        ),
    },
    {
        "name": "Account Creation → Added to Admin Group",
        "sequence": [4720, 4728],
        "min_repeats": {},
        "severity": "Critical",
        "description": (
            "A user-account creation event and an administrator "
            "group membership change were observed close together. "
            "Verify the account and group membership change."
        ),
    },
    {
        "name": "Credential Access → Log Cleared",
        "sequence": [5379, 1102],
        "min_repeats": {},
        "severity": "Critical",
        "description": (
            "Credential Manager access and a security-log-cleared "
            "event were observed close together. Investigate the "
            "sequence; this alone does not establish causation."
        ),
    },
]


# ============================================================
# BASIC FIELD HELPERS
# ============================================================

def _event_id(event):
    """Return a normalized Windows Event ID."""

    try:
        return int(event.get("event_id"))
    except (TypeError, ValueError):
        return None


def _host(event):
    """Normalize the event hostname."""

    return str(
        event.get("hostname")
        or event.get("host")
        or "local"
    ).strip().lower()


def _user(event):
    """Normalize the event username."""

    return str(
        event.get("user")
        or "Unknown"
    ).strip().lower()


def _logon_id(event):
    """Return a normalized Logon ID or an empty string."""

    value = event.get("logon_id")

    if value is None:
        return ""

    value = str(value).strip()

    if value.lower() in {"", "unknown", "n/a", "none"}:
        return ""

    return value.lower()


def _severity(event):
    """Normalize event severity."""

    value = str(event.get("severity") or "Info").strip().title()

    return value if value in SEVERITY_ORDER else "Info"


# ============================================================
# TIME PARSER
# ============================================================

def _parse_time(value):
    """
    Parse common Windows event timestamps, including ISO
    timestamps with fractional seconds or timezone offsets.

    Invalid timestamps return None rather than being treated
    as proof that an entire group falls within a time window.
    """

    if isinstance(value, datetime):
        parsed = value

    elif value is None:
        return None

    else:
        value = str(value).strip()

        if not value:
            return None

        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        parsed = None

        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            pass

        if parsed is None:
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%m/%d/%Y %I:%M:%S %p",
                "%m/%d/%Y %H:%M:%S",
                "%d-%m-%Y %H:%M:%S",
            ]

            for fmt in formats:
                try:
                    parsed = datetime.strptime(value, fmt)
                    break
                except ValueError:
                    continue

        if parsed is None:
            return None

    # Normalize timezone-aware values to UTC-naive values
    # for consistent comparisons.
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(
            tzinfo=None
        )

    return parsed


def _event_time(event):
    """Read an event's normalized timestamp."""

    return _parse_time(
        event.get("time")
        or event.get("timestamp")
        or event.get("created_at")
    )


def _within_window(events, window_minutes):
    """Return True only when timestamps can be verified."""

    if len(events) < 2:
        return False

    times = [_event_time(event) for event in events]

    # Do not accept an unverified time window.
    if any(value is None for value in times):
        return False

    return (
        max(times) - min(times)
        <= timedelta(minutes=window_minutes)
    )


# ============================================================
# LOGON SESSION VALIDATION
# ============================================================

def _same_logon_id(first_event, second_event):
    """Require two matching, known Logon IDs."""

    first_id = _logon_id(first_event)
    second_id = _logon_id(second_event)

    return bool(first_id and second_id and first_id == second_id)


def _context_matches(pattern, incident_events):
    """Check additional context required by a pattern."""

    if not pattern.get("require_same_logon_id", False):
        return True

    if len(incident_events) < 2:
        return False

    login_event = incident_events[0]
    privilege_event = incident_events[-1]

    return (
        _event_id(login_event) == 4624
        and _event_id(privilege_event) == 4672
        and _same_logon_id(login_event, privilege_event)
    )


# ============================================================
# SEVERITY TO RISK SCORE
# ============================================================

def _severity_to_score(severity):
    """Map a severity to its configured base score."""

    severity = str(severity or "Info").strip().title()

    return SEVERITY_SCORES.get(severity, 0)


# ============================================================
# INCIDENT CREATION HELPER
# ============================================================

def _make_incident(
    incident_type,
    name,
    severity,
    description,
    events,
):
    """Create a consistent incident dictionary."""

    ordered_events = sorted(
        events,
        key=lambda event: _event_time(event) or datetime.min
    )

    valid_times = [
        _event_time(event)
        for event in ordered_events
        if _event_time(event) is not None
    ]

    start_time = (
        min(valid_times).isoformat(sep=" ")
        if valid_times else ""
    )

    end_time = (
        max(valid_times).isoformat(sep=" ")
        if valid_times else ""
    )

    return {
        "type": incident_type,
        "name": name,
        "severity": severity,
        "description": description,
        "event_count": len(ordered_events),
        "events": ordered_events,
        "start_time": start_time,
        "end_time": end_time,
        "score": _severity_to_score(severity),
    }


# ============================================================
# PATTERN MATCHING
# ============================================================


def _match_patterns(sorted_events, used_indices):
    """Detect ordered patterns using host, user, and time constraints."""

    incidents = []

    for pattern in ATTACK_PATTERNS:
        sequence = pattern["sequence"]
        required_repeats = pattern.get("min_repeats", {})
        is_brute_force = sequence == [4625, 4624]

        candidates = [
            (idx, event)
            for idx, event in sorted_events
            if idx not in used_indices
        ]

        for start_position, (first_idx, first_event) in enumerate(candidates):
            if _event_id(first_event) != sequence[0]:
                continue

            first_time = _event_time(first_event)
            if first_time is None:
                continue

            first_host = _host(first_event)
            first_user = _user(first_event)

            matched = [(first_idx, first_event)]
            failed_count = 1 if is_brute_force else 0
            successful_login = None

            for idx, event in candidates[start_position + 1:]:
                event_id = _event_id(event)
                event_time = _event_time(event)

                if event_time is None:
                    continue

                # Stop when the candidate is outside the time window.
                if event_time - first_time > timedelta(
                    minutes=CORRELATION_WINDOW_MINUTES
                ):
                    break

                # Never combine events from different hosts or users.
                if _host(event) != first_host:
                    continue

                if _user(event) != first_user:
                    continue

                if is_brute_force:
                    if event_id == 4625:
                        matched.append((idx, event))
                        failed_count += 1
                        continue

                    if event_id == 4624:
                        successful_login = (idx, event)
                        break

                    continue

                expected_id = sequence[len(matched)]

                if event_id != expected_id:
                    continue

                if (
                    pattern.get("require_same_logon_id", False)
                    and len(matched) == 1
                    and not _same_logon_id(first_event, event)
                ):
                    continue

                matched.append((idx, event))

                if len(matched) == len(sequence):
                    break

            if is_brute_force:
                if successful_login is None:
                    continue

                if failed_count < required_repeats.get(4625, 1):
                    continue

                matched.append(successful_login)

            if len(matched) < len(sequence):
                continue

            matched_events = [event for _, event in matched]

            if not _within_window(
                matched_events,
                CORRELATION_WINDOW_MINUTES
            ):
                continue

            if not _context_matches(pattern, matched_events):
                continue

            incident = _make_incident(
                "pattern",
                pattern["name"],
                pattern["severity"],
                pattern["description"],
                matched_events,
            )

            incidents.append(incident)

            for idx, _ in matched:
                used_indices.add(idx)

    return incidents



# ============================================================
# FREQUENCY DETECTION
# ===========

def _match_frequency(sorted_events, used_indices):
    """
    Group repeated events into fixed, non-overlapping time windows.

    Events are grouped by:
      - Event ID
      - Hostname
      - Username

    Each time window produces at most one frequency incident.
    """

    buckets = {}

    for idx, event in sorted_events:
        if idx in used_indices:
            continue

        event_id = _event_id(event)

        if event_id is None:
            continue

        if event_id in FREQUENCY_EXCLUDED_EVENT_IDS:
            continue

        event_time = _event_time(event)

        if event_time is None:
            continue

        key = (
            event_id,
            _host(event),
            _user(event),
        )

        buckets.setdefault(key, []).append(
            (event_time, idx, event)
        )

    incidents = []

    for (event_id, hostname, username), entries in buckets.items():
        entries.sort(key=lambda item: item[0])

        position = 0

        while position < len(entries):
            # Anchor the window to its first event so the same
            # burst does not generate an alert for every new event.
            window_start = entries[position][0]
            window_end = window_start + timedelta(
                minutes=FREQUENCY_WINDOW_MINUTES
            )

            group = []

            while position < len(entries):
                event_time, idx, event = entries[position]

                if event_time > window_end:
                    break

                group.append((event_time, idx, event))
                position += 1

            if len(group) < FREQUENCY_THRESHOLD:
                continue

            group_events = [item[2] for item in group]

            severity = max(
                (_severity(item) for item in group_events),
                key=lambda value: SEVERITY_ORDER[value],
            )

            name = (
                f"Repeated Event ID {event_id} "
                f"({len(group_events)}x)"
            )

            description = (
                f"{len(group_events)} occurrences of Event ID "
                f"{event_id} "
                f"({group_events[0].get('name', 'Windows Event')}) "
                f"for host {hostname} and user {username} within "
                f"{FREQUENCY_WINDOW_MINUTES} minutes."
            )

            incident = _make_incident(
                "frequency",
                name,
                severity,
                description,
                group_events,
            )

            incident["hostname"] = hostname
            incident["user"] = username

            incidents.append(incident)

            for _, event_idx, _ in group:
                used_indices.add(event_idx)

    return incidents


# ============================================================
# DEDUPLICATION
# ============================================================


def _incident_logon_ids(incident):
    """Return the known Logon IDs in an incident."""

    logon_ids = {
        _logon_id(event)
        for event in incident.get("events", [])
        if _logon_id(event)
    }

    return tuple(sorted(logon_ids))



def _deduplicate_incidents(incidents):
    """
    Merge repeated pattern incidents for the same known session.
    Keep unrelated sessions and frequency incidents separate.
    """

    merged = {}
    result = []

    for incident in incidents:
        events = incident.get("events", [])

        # Only merge pattern incidents with a known session.
        logon_ids = _incident_logon_ids(incident)

        can_merge = (
            incident.get("type") == "pattern"
            and bool(logon_ids)
        )

        if not can_merge:
            result.append(incident)
            continue

        key = (
            incident.get("type"),
            incident.get("name"),
            incident.get("hostname", "local"),
            incident.get("user", "Unknown"),
            logon_ids,
        )

        if key not in merged:
            new_incident = dict(incident)
            new_incident["events"] = list(events)
            new_incident["event_count"] = len(events)
            new_incident["occurrences"] = 1

            merged[key] = new_incident
            result.append(new_incident)
            continue

        existing = merged[key]
        existing_events = existing.get("events", [])

        known_keys = {
            (
                event.get("record_id"),
                event.get("event_id"),
                event.get("time"),
            )
            for event in existing_events
        }

        for event in events:
            event_key = (
                event.get("record_id"),
                event.get("event_id"),
                event.get("time"),
            )

            if event_key not in known_keys:
                existing_events.append(event)
                known_keys.add(event_key)

        existing_events.sort(
            key=lambda event: event.get("time") or ""
        )

        existing["events"] = existing_events
        existing["event_count"] = len(existing_events)
        existing["occurrences"] += 1

        if existing_events:
            existing["start_time"] = (
                existing_events[0].get("time", "")
            )
            existing["end_time"] = (
                existing_events[-1].get("time", "")
            )

    return result



# ============================================================
# CORRELATE ONE HOST/USER GROUP
# ============================================================

def _correlate_group(events):
    """Correlate events for one host and user."""

    sorted_events = sorted(
        enumerate(events),
        key=lambda item: _event_time(item[1]) or datetime.min
    )

    used_indices = set()
    incidents = []

    incidents.extend(
        _match_patterns(sorted_events, used_indices)
    )

    incidents.extend(
        _match_frequency(sorted_events, used_indices)
    )

    # Add MITRE technique information from the incident's events.
    for incident in incidents:
        techniques = []
        seen = set()

        for event in incident.get("events", []):
            mitre_id = event.get("mitre_id")

            if mitre_id and mitre_id not in seen:
                seen.add(mitre_id)

                techniques.append({
                    "id": mitre_id,
                    "tactic": event.get("mitre_tactic"),
                })

        incident["mitre_techniques"] = techniques

    return incidents


# ============================================================
# MAIN CORRELATION FUNCTION
# ============================================================

def correlate_events(events):
    """
    Main entry point used by the existing Flask application.

    Groups events by hostname and username, correlates each group,
    enriches incidents, removes exact duplicates, and sorts newest
    incidents first.
    """

    by_group = {}

    for event in events:
        key = (
            _host(event),
            _user(event),
        )

        by_group.setdefault(key, []).append(event)

    incidents = []

    for (hostname, username), group_events in by_group.items():
        group_incidents = _correlate_group(group_events)

        for incident in group_incidents:
            incident["hostname"] = hostname
            incident["user"] = username

        incidents.extend(group_incidents)

    incidents = _deduplicate_incidents(incidents)

    incidents.sort(
        key=lambda incident: (
            _parse_time(incident.get("start_time"))
            or datetime.min
        ),
        reverse=True,
    )

    return incidents
