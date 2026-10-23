from modules.security_monitor import get_security_events

events = get_security_events()

for event in events[:10]:
    print(event)
