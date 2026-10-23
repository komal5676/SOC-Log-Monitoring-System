import win32evtlog


# ============================================================
# WINDOWS EVENT LOG READER
# ============================================================

MAX_EVENTS_TO_READ = 5000


def read_windows_events():

    server = "localhost"
    log_type = "Security"

    hand = None

    try:

        hand = win32evtlog.OpenEventLog(
            server,
            log_type
        )

        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ |
            win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        all_events = []

        while len(all_events) < MAX_EVENTS_TO_READ:

            events = win32evtlog.ReadEventLog(
                hand,
                flags,
                0
            )

            if not events:
                break

            remaining = (
                MAX_EVENTS_TO_READ
                - len(all_events)
            )

            all_events.extend(
                events[:remaining]
            )

            if len(all_events) >= MAX_EVENTS_TO_READ:
                break

        return all_events

    finally:

        if hand:

            win32evtlog.CloseEventLog(
                hand
            )
