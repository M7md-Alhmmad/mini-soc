from src.database import (
    get_incidents,
    update_incident_status,
    update_incident_note
)


def show_incidents():

    incidents = get_incidents()

    print("\nCURRENT INCIDENTS")
    print("=" * 70)

    for incident in incidents:

        (
            incident_id,
            incident_type,
            severity,
            username,
            ip_address,
            failed_attempts,
            timestamp,
            status,
            mitre_technique,
            analyst_note,
            risk_score
        ) = incident

        print(f"ID: {incident_id}")
        print(f"Type: {incident_type}")
        print(f"Severity: {severity}")
        print(f"User: {username}")
        print(f"IP: {ip_address}")
        print(f"Failed Attempts: {failed_attempts}")
        print(f"MITRE: {mitre_technique}")
        print(f"Status: {status}")
        print(f"Note: {analyst_note}")
        print(f"Risk Score: {risk_score}/100")
        print("-" * 70)


def investigate_incident(incident_id):

    update_incident_status(
        incident_id,
        "INVESTIGATING"
    )

    print(f"Incident {incident_id} is now INVESTIGATING.")


def resolve_incident(incident_id, note):

    update_incident_status(
        incident_id,
        "RESOLVED"
    )

    update_incident_note(
        incident_id,
        note
    )

    print(f"Incident {incident_id} has been RESOLVED.")


if __name__ == "__main__":

    show_incidents()

    print("\nCommands:")
    print("1 - Investigate incident")
    print("2 - Resolve incident")
    print("3 - Exit")

    choice = input("\nChoose an option: ")

    if choice == "1":

        incident_id = int(
            input("Enter incident ID: ")
        )

        investigate_incident(incident_id)

    elif choice == "2":

        incident_id = int(
            input("Enter incident ID: ")
        )

        note = input(
            "Enter analyst note: "
        )

        resolve_incident(
            incident_id,
            note
        )

    elif choice == "3":

        print("Exiting...")
