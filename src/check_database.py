from .database import get_events

events = get_events()

print(f"Total events: {len(events)}")

for event in events[:10]:
    print(event)
