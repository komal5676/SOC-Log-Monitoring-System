
# ============================================================
# SENTINELX - EXPLAINABLE RISK ENGINE
# ============================================================

from datetime import datetime, timedelta, timezone


# ------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------

SEVERITY_SCORES = {
    "Critical": 90,
    "High": 70,
    "Medium": 40,
    "Low": 10,
    "Info": 0
}

MAX_RISK_SCORE = 100

# Additional points for repeated failed logins
REPETITION_POINTS = {
    3: 5,
    5: 10,
    10: 15
}

# Failed logins are grouped within this time window
FAILED_LOGIN_WINDOW_MINUTES = 15


# ------------------------------------------------------------
# GENERAL HELPERS
# ------------------------------------------------------------

def normalize_event_id(event):
    """Return a normalized Windows event ID as a string."""

    value = event.get("event_id", "")

    if value is None:
        return ""

    return str(value).strip()


def normalize_severity(value):
    """Normalize severity labels."""

    severity = str(value or "Info").strip().title()

    if severity not in SEVERITY_SCORES:
        return "Info"

    return severity


def get_event_host(event):
    """Return the best available hostname."""

    return str(
        event.get("hostname")
        or event.get("host")
        or event.get("source")
        or "unknown-host"
    ).strip().lower()


def get_event_user(event):
    """Return the best available username."""

    return str(
        event.get("user")
        or "unknown-user"
    ).strip().lower()


def get_event_timestamp(event):
    """
    Parse common event timestamp formats.

    Supported fields:
    time, timestamp, created_at, and TimeCreated.

    Returns None if the timestamp cannot be parsed.
    """

    raw_value = (
        event.get("time")
        or event.get("timestamp")
        or event.get("created_at")
        or event.get("TimeCreated")
    )

    if not raw_value:
        return None

    if isinstance(raw_value, datetime):
        parsed = raw_value

    elif isinstance(raw_value, (int, float)):
        try:
            parsed = datetime.fromtimestamp(
                raw_value,
                tz=timezone.utc
            )
        except (ValueError, OSError, OverflowError):
            return None

    else:
        value = str(raw_value).strip()

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

    # Normalize timestamps to UTC-naive datetimes so comparisons
    # do not fail when some timestamps contain timezone offsets.
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)

    return parsed


def get_repetition_points(repeat_count):
    """Return the repetition bonus for an activity count."""

    bonus = 0

    for threshold, points in sorted(REPETITION_POINTS.items()):
        if repeat_count >= threshold:
            bonus = points

    return bonus


# ------------------------------------------------------------
# RISK LEVEL
# ------------------------------------------------------------

def get_risk_level(score):
    """Convert a numerical risk score into a risk level."""

    try:
        score = int(score)
    except (TypeError, ValueError):
        score = 0

    score = max(0, min(MAX_RISK_SCORE, score))

    if score >= 90:
        return "Critical"
    elif score >= 70:
        return "High"
    elif score >= 40:
        return "Medium"
    elif score > 0:
        return "Low"

    return "Info"


# ------------------------------------------------------------
# EVENT BASE SCORE
# ------------------------------------------------------------


def calculate_event_score(event):
    """Calculate the base risk score for one event."""

    severity = normalize_severity(event.get("severity"))
    event_id = normalize_event_id(event)

    # Privilege assignment alone does not establish malicious activity.
    # Keep the event classified as High, but use a lower base risk score.
    if event_id == "4672":
        return 20

    return SEVERITY_SCORES[severity]



# ------------------------------------------------------------
# FAILED LOGIN ANALYSIS
# ------------------------------------------------------------

def count_failed_logins_in_window(event, events):
    """
    Count failed logins for the same host and user within
    the configured time window.

    Event ID 4625 represents a failed Windows logon.

    If the current event has no usable timestamp, it is treated
    as a single failure rather than assuming unrelated historical
    failures happened together.
    """

    if normalize_event_id(event) != "4625":
        return 1

    event_time = get_event_timestamp(event)

    if event_time is None:
        return 1

    target_host = get_event_host(event)
    target_user = get_event_user(event)

    window_start = event_time - timedelta(
        minutes=FAILED_LOGIN_WINDOW_MINUTES
    )

    count = 0

    for candidate in events:
        if normalize_event_id(candidate) != "4625":
            continue

        if get_event_host(candidate) != target_host:
            continue

        if get_event_user(candidate) != target_user:
            continue

        candidate_time = get_event_timestamp(candidate)

        if candidate_time is None:
            continue

        if window_start <= candidate_time <= event_time:
            count += 1

    return max(1, count)


# ------------------------------------------------------------
# EXPLAINABLE EVENT RISK
# ------------------------------------------------------------

def explain_event_risk(event, repeated_failures=1):
    """
    Calculate an event score and explain the evidence.

    Repetition bonuses apply only to failed login events.
    """

    severity = normalize_severity(event.get("severity"))
    score = calculate_event_score(event)
    reasons = []

    event_id = normalize_event_id(event)

    reasons.append(
        f"Base score {score} assigned for {severity} severity."
    )

    # Only failed logins receive the repetition bonus.
    if event_id == "4625":

        try:
            repeat_count = max(1, int(repeated_failures))
        except (TypeError, ValueError):
            repeat_count = 1

        bonus = get_repetition_points(repeat_count)

        if bonus > 0:
            score += bonus

            reasons.append(
                f"{repeat_count} failed logins were observed for "
                f"the same host and account within "
                f"{FAILED_LOGIN_WINDOW_MINUTES} minutes. "
                f"Repetition bonus: +{bonus}."
            )

        else:
            reasons.append(
                "Fewer than 3 failed logins were observed in the "
                "analysis window. No repetition bonus applied."
            )

    score = min(MAX_RISK_SCORE, max(0, score))

    return {
        "risk_score": score,
        "risk_level": get_risk_level(score),
        "risk_reasons": reasons
    }


# ------------------------------------------------------------
# INCIDENT SCORE
# ------------------------------------------------------------

def calculate_incident_score(incident):
    """
    Calculate incident risk from its assigned severity.

    Associated event count alone does not increase incident risk.
    A large number of events may represent routine system activity.
    """

    severity = normalize_severity(incident.get("severity"))

    score = SEVERITY_SCORES[severity]

    return min(MAX_RISK_SCORE, max(0, score))


# ------------------------------------------------------------
# MAIN RISK CALCULATION
# ------------------------------------------------------------

def calculate_risk(events, incidents):
    """
    Score individual events and correlated incidents.

    Failed logins:
        Grouped by hostname and username within a 15-minute window.

    Incidents:
        Scored using the correlation rule's severity.

    Overall risk:
        Highest individual event or incident score.

    Return structure remains compatible with the existing Flask app.
    """

    # --------------------------------------------------------
    # SCORE INDIVIDUAL EVENTS
    # --------------------------------------------------------

    scored_events = []

    for event in events:
        event_copy = dict(event)

        repeat_count = count_failed_logins_in_window(
            event,
            events
        )

        risk = explain_event_risk(
            event,
            repeated_failures=repeat_count
        )

        event_copy.update(risk)
        scored_events.append(event_copy)

    # --------------------------------------------------------
    # SCORE CORRELATED INCIDENTS
    # --------------------------------------------------------

    scored_incidents = []

    for incident in incidents:
        incident_copy = dict(incident)

        severity = normalize_severity(
            incident.get("severity")
        )

        final_score = calculate_incident_score(incident)

        incident_events = incident.get("events", [])

        if not isinstance(incident_events, list):
            incident_events = []

        event_count = incident.get("event_count")

        if event_count is None:
            event_count = len(incident_events)

        try:
            event_count = int(event_count)
        except (TypeError, ValueError):
            event_count = len(incident_events)

        reasons = [
            f"Base score {final_score} assigned for "
            f"{severity} incident severity."
        ]

        reasons.append(
            "No repetition bonus applied to the incident score. "
            "Event count alone does not establish malicious activity."
        )

        reasons.append(
            f"{event_count} associated event(s) recorded for "
            "investigation."
        )

        incident_copy["risk_score"] = final_score
        incident_copy["risk_level"] = get_risk_level(final_score)
        incident_copy["risk_reasons"] = reasons

        scored_incidents.append(incident_copy)

    # --------------------------------------------------------
    # CALCULATE OVERALL RISK
    # --------------------------------------------------------

    all_scores = [
        item["risk_score"]
        for item in scored_events + scored_incidents
    ]

    overall_score = max(all_scores, default=0)
    overall_level = get_risk_level(overall_score)

    # --------------------------------------------------------
    # RETURN EXISTING STRUCTURE
    # --------------------------------------------------------

    return {
        "events": scored_events,
        "incidents": scored_incidents,
        "overall_score": overall_score,
        "overall_level": overall_level
    }
