
import random
import time
from datetime import datetime, timedelta

from modules.correlation_engine import correlate_events


def make_events(count):
    events = []
    start = datetime(2026, 10, 21, 10, 0, 0)

    event_ids = [4624, 4625, 4672, 4688, 4720, 4728, 4799, 5379, 1102]
    severities = {
        4624: "Low",
        4625: "Medium",
        4672: "High",
        4688: "Medium",
        4720: "High",
        4728: "Critical",
        4799: "Medium",
        5379: "Medium",
        1102: "Critical",
    }

    for i in range(count):
        event_id = random.choice(event_ids)
        event_time = start + timedelta(seconds=i)

        events.append({
            "record_id": i + 1,
            "event_id": event_id,
            "name": f"Test Event {event_id}",
            "severity": severities[event_id],
            "hostname": f"LAB-PC-{(i % 3) + 1}",
            "user": f"testuser{(i % 5) + 1}",
            "logon_id": f"0x{i % 100:04x}",
            "time": event_time.isoformat(sep=" "),
            "mitre_id": None,
            "mitre_tactic": None,
        })

    return events


for count in [500, 1000, 2000, 5000]:
    events = make_events(count)

    started = time.perf_counter()
    incidents = correlate_events(events)
    elapsed = time.perf_counter() - started

    print(
        f"Events: {count:5} | "
        f"Time: {elapsed:.3f}s | "
        f"Incidents: {len(incidents)}"
    )
