import win32evtlog


LOG_NAME = "Security"
TARGET_EVENT_ID = 5379
MAX_EVENTS = 20


def check_5379_events():
	print("=" * 70)
	print("CHECKING WINDOWS EVENT ID 5379 TIMESTAMPS")
	print("=" * 70)

	hand = win32evtlog.OpenEventLog(None, LOG_NAME)
	flags = (
		win32evtlog.EVENTLOG_BACKWARDS_READ
		| win32evtlog.EVENTLOG_SEQUENTIAL_READ
	)

	found = 0

	try:
		while found < MAX_EVENTS:
			events = win32evtlog.ReadEventLog(hand, flags, 0)
			if not events:
				break

			for event in events:
				event_id = event.EventID & 0xFFFF
				if event_id != TARGET_EVENT_ID:
					continue

				print(f"Record ID: {event.RecordNumber}")
				print(f"Event ID : {event_id}")
				print(f"Time     : {event.TimeGenerated}")
				print("-" * 70)

				found += 1
				if found >= MAX_EVENTS:
					break
	finally:
		win32evtlog.CloseEventLog(hand)

	print("=" * 70)
	print(f"Found {found} Event ID 5379 records")
	print("=" * 70)


if __name__ == "__main__":
	check_5379_events()
