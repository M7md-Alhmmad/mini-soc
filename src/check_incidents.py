from .database import get_incidents

incidents = get_incidents()

print(f"Total incidents: {len(incidents)}")

for incident in incidents:
    print(incident)
