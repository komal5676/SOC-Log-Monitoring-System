from config import MAX_EVENTS_PER_INGEST


REQUIRED_EVENT_FIELDS = {
    "event_id",
    "name",
    "severity",
    "category",
    "description",
    "source",
    "time"
}

VALID_SEVERITIES = {
    "Critical",
    "High",
    "Medium",
    "Low",
    "Info"
}

MAX_STRING_LENGTH = 500


def validate_payload(data):
    """
    Validate the complete event ingestion payload.

    Returns:
        (True, None) when valid
        (False, error_message) when invalid
    """

    if not isinstance(data, dict):
        return False, "Payload must be a JSON object."

    hostname = data.get("hostname")
    events = data.get("events")

    if not hostname or not isinstance(hostname, str):
        return False, "Missing or invalid 'hostname'."

    if len(hostname) > 100:
        return False, "'hostname' is too long."

    if not isinstance(events, list):
        return False, "'events' must be a list."

    if len(events) > MAX_EVENTS_PER_INGEST:
        return False, (
            f"Too many events in one request "
            f"(max {MAX_EVENTS_PER_INGEST})."
        )

    for i, event in enumerate(events):

        ok, error = _validate_event(event)

        if not ok:
            return False, (
                f"Event at index {i} invalid: {error}"
            )

    return True, None


def _validate_event(event):

    if not isinstance(event, dict):
        return False, "must be an object"

    missing = REQUIRED_EVENT_FIELDS - event.keys()

    if missing:
        return False, (
            f"missing fields {sorted(missing)}"
        )

    if not isinstance(event.get("event_id"), int):
        return False, "'event_id' must be an integer"

    if event.get("severity") not in VALID_SEVERITIES:
        return False, (
            f"'severity' must be one of "
            f"{sorted(VALID_SEVERITIES)}"
        )

    for field in (
        "name",
        "category",
        "description",
        "source",
        "time"
    ):

        value = event.get(field)

        if (
            not isinstance(value, str)
            or len(value) > MAX_STRING_LENGTH
        ):
            return False, (
                f"'{field}' must be a string under "
                f"{MAX_STRING_LENGTH} chars"
            )

    user = event.get("user")

    if user is not None and (
        not isinstance(user, str)
        or len(user) > MAX_STRING_LENGTH
    ):
        return False, "'user' must be a string"

    return True, None