import requests
from datetime import datetime, timedelta
from datetime import datetime


URL = "http://127.0.0.1:5000/ingest"

import os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.environ.get("API_KEY")

start = datetime.now().replace(microsecond=0)


events = [

	{
		"record_id": 910001,
		"event_id": 4720,
		"name": "User Account Created",
		"severity": "High",
		"category": "Account Management",
		"description": "A new user account was created.",
		"mitre_id": "T1136",
		"mitre_tactic": "Persistence — Create Account",
		"source": "TEST",
		"user": "test-admin",
		"logon_id": "0xTEST002",
		"time": str(start)
	},

	{
		"record_id": 910002,
		"event_id": 4728,
		"name": "User Added to Administrator Group",
		"severity": "Critical",
		"category": "Privilege",
		"description": "A user was added to the Administrators group.",
		"mitre_id": "T1098",
		"mitre_tactic": "Persistence — Account Manipulation",
		"source": "TEST",
		"user": "test-admin",
		"logon_id": "0xTEST002",
		"time": str(start + timedelta(seconds=30))
	}

]


payload = {
	"hostname": "SOC-TEST-ACCOUNT",
	"events": events
}


headers = {
	"X-API-Key": API_KEY
}


response = requests.post(
	URL,
	json=payload,
	headers=headers,
	timeout=10
)


print("Status:", response.status_code)
print("Response:", response.text)
