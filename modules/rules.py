from datetime import datetime, timedelta, timezone

from config import (
    FAILED_LOGIN_THRESHOLD,
    FAILED_LOGIN_WINDOW_MINUTES,
)


def get_detection_rules():
    return [
        {
            "id": "RULE-001",
            "name": "Repeated Failed Logins",
            "event_id": 4625,
            "threshold": FAILED_LOGIN_THRESHOLD,
            "window_minutes": FAILED_LOGIN_WINDOW_MINUTES,
            "severity": "High",
            "enabled": True,
        }
    ]


def parse_event_time(value):
    """Parse an ISO-formatted event timestamp."""
    if not value:
        return None

    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(
                str(value).replace("Z", "+00:00")
            )
        except (ValueError, TypeError):
            return None

    # Treat timestamps without timezone information as UTC.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def evaluate_failed_logins(events, now=None):
    """Detect repeated failed logins within the configured time window."""
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)

    alerts = []

    for rule in get_detection_rules():
        if not rule["enabled"]:
            continue

        cutoff = now - timedelta(
            minutes=rule["window_minutes"]
        )
        grouped_events = {}

        for event in events:
            try:
                event_id = int(event.get("event_id", 0))
            except (TypeError, ValueError):
                continue

            if event_id != rule["event_id"]:
                continue

            event_time = parse_event_time(
                event.get("time") or event.get("timestamp")
            )

            # Ignore events without a valid timestamp or
            # events outside the current detection window.
            if event_time is None or not (cutoff <= event_time <= now):
                continue

            hostname = (
                event.get("hostname")
                or event.get("host")
                or "Unknown host"
            )
            username = event.get("user") or "Unknown user"

            key = (hostname, username)
            grouped_events.setdefault(key, []).append(event)

        for (hostname, username), matching_events in grouped_events.items():
            if len(matching_events) >= rule["threshold"]:
                alerts.append({
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "hostname": hostname,
                    "user": username,
                    "count": len(matching_events),
                    "threshold": rule["threshold"],
                    "window_minutes": rule["window_minutes"],
                    "severity": rule["severity"],
                    "description": (
                        f"{len(matching_events)} failed logins detected "
                        f"for {username} on {hostname} within "
                        f"{rule['window_minutes']} minutes."
                    ),
                })

    return alerts