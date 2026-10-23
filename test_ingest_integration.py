import requests
from datetime import datetime, timedelta
from config import API_KEY

url = "http://127.0.0.1:5000/ingest"
now = datetime.now()
hostname = "SENTINELX-DEMO-PC"
events = []

samples = [
    (4625, "Failed Login", "Medium"),
    (4625, "Failed Login", "Medium"),
    (4625, "Failed Login", "Medium"),
    (4624, "Successful Login", "Low"),
]

for i, (event_id, name, severity) in enumerate(samples):
    timestamp = now - timedelta(seconds=30 - i * 5)
    events.append({
        "event_id": event_id,
        "name": name,
        "severity": severity,
        "category": "Authentication",
        "description": "Controlled SentinelX integration test event",
        "source": "SentinelX Demo",
        "time": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "user": "sentinelx_demo_user",
        "logon_id": "0xDEMO123",
        "record_id": 99000000 + i
    })

try:
    response = requests.post(
        url,
        json={"hostname": hostname, "events": events},
        headers={"X-API-Key": API_KEY},
        timeout=15
    )
    print("HTTP status:", response.status_code)
    print("Response:", response.text)
except requests.RequestException as exc:
    print("Request failed:", exc)
