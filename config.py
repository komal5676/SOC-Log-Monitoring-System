import os

# API key used by agents when sending events to /ingest
API_KEY = os.environ.get(
    "API_KEY",
)

# Optional webhook for High/Critical alerts
ALERT_WEBHOOK_URL = os.environ.get(
    "SOC_ALERT_WEBHOOK_URL",
    ""
)

# Risk score at which an alert is triggered
ALERT_RISK_THRESHOLD = 70

# Maximum events accepted in one request
MAX_EVENTS_PER_INGEST = 500

# Detection rule settings
FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW_MINUTES = 5