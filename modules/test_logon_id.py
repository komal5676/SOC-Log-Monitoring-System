import sys
import os

# Add SOC_Project to Python path
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.insert(0, PROJECT_ROOT)

from modules.event_reader import read_windows_events


print("\n========== WINDOWS LOGON ID TEST ==========\n")

events = read_windows_events()

found = 0

for event in events:

    event_id = event.EventID & 0xFFFF

    if event_id not in (4624, 4625, 4672):
        continue

    print("----------------------------------------")
    print("Event ID  :", event_id)
    print("Record ID :", getattr(event, "RecordNumber", "Unknown"))
    print("Time      :", event.TimeGenerated)

    inserts = getattr(
        event,
        "StringInserts",
        None
    )

    print("\nStringInserts:")

    if not inserts:
        print("No StringInserts")
        continue

    for index, value in enumerate(inserts):

        print(
            f"[{index}] = {value}"
        )

    found += 1

    if found >= 10:
        break


print("\n========== TEST COMPLETE ==========\n")