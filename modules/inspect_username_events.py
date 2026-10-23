
import win32evtlog

EVENT_IDS = {4624, 4625, 4672, 4688}
MAX_MATCHES = 2

handle = None
matches = 0

try:
    handle = win32evtlog.OpenEventLog("localhost", "Security")

    flags = (
        win32evtlog.EVENTLOG_BACKWARDS_READ
        | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    )

    while matches < MAX_MATCHES * len(EVENT_IDS):
        events = win32evtlog.ReadEventLog(handle, flags, 0)

        if not events:
            break

        for event in events:
            event_id = int(event.EventID) & 0xFFFF

            if event_id not in EVENT_IDS:
                continue

            print(f"\nEvent ID: {event_id}")
            print("Has XML:", bool(getattr(event, "Xml", None)))
            print("Event source:", getattr(event, "SourceName", "Unknown"))
            print("StringInserts:")

            for index, value in enumerate(event.StringInserts or []):
                print(f"  [{index}] {value!r}")

            matches += 1

            if matches >= MAX_MATCHES * len(EVENT_IDS):
                break

finally:
    if handle:
        win32evtlog.CloseEventLog(handle)

