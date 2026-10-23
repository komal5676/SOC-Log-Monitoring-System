from modules.database import read_events
from modules.correlation_engine import correlate_events
from modules.risk_engine import calculate_risk


events = read_events(limit=5000)
incidents = correlate_events(events)
result = calculate_risk(events, incidents)

print("\n=== OVERALL RISK ===")
print("Score:", result["overall_score"])
print("Level:", result["overall_level"])

print("\n=== HIGHEST-RISK EVENTS ===")
for event in sorted(
    result["events"],
    key=lambda item: item.get("risk_score", 0),
    reverse=True
)[:10]:
    print({
        "event_id": event.get("event_id"),
        "hostname": event.get("hostname"),
        "user": event.get("user"),
        "severity": event.get("severity"),
        "risk_score": event.get("risk_score"),
        "risk_level": event.get("risk_level"),
    })

print("\n=== HIGHEST-RISK INCIDENTS ===")
for incident in sorted(
    result["incidents"],
    key=lambda item: item.get("risk_score", 0),
    reverse=True
)[:10]:
    print({
        "title": incident.get("title"),
        "severity": incident.get("severity"),
        "risk_score": incident.get("risk_score"),
        "risk_level": incident.get("risk_level"),
    })

