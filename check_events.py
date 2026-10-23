from modules.event_reader import read_windows_events

events = read_windows_events()

count = 0

for event in events:
    print("Event ID:", event.EventID & 0xFFFF)
    print("Source:", event.SourceName)
    print("Time:", event.TimeGenerated)
    print("-" * 40)

    count += 1

    if count == 10:
        break