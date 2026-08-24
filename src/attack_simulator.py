from datetime import datetime

from .database import insert_event


def simulate_brute_force(
    username="admin",
    ip_address="203.0.113.50",
    attempts=10
):

    print("[ATTACK] Starting brute-force simulation...")
    print(f"[ATTACK] Target user: {username}")
    print(f"[ATTACK] Source IP: {ip_address}")
    print(f"[ATTACK] Attempts: {attempts}")
    print()

    for attempt in range(1, attempts + 1):

        timestamp = datetime.now().isoformat()

        insert_event(
            timestamp=timestamp,
            event_type="LOGIN_FAILED",
            username=username,
            ip_address=ip_address
        )

        print(
            f"[ATTACK] Failed login "
            f"{attempt}/{attempts}"
        )

    print()
    print("[ATTACK] Simulation complete.")
    print("[ATTACK] Logs inserted into database.")


def simulate_port_scan(
    username="scanner",
    ip_address="198.51.100.25",
    ports=20
):

    print("[ATTACK] Starting port-scan simulation...")
    print(f"[ATTACK] Source IP: {ip_address}")
    print(f"[ATTACK] Ports scanned: {ports}")
    print()

    for port in range(1, ports + 1):

        timestamp = datetime.now().isoformat()

        insert_event(
            timestamp=timestamp,
            event_type="PORT_SCAN",
            username=username,
            ip_address=ip_address
        )

        print(
            f"[ATTACK] Port "
            f"{port}/{ports} scanned"
        )

    print()
    print("[ATTACK] Port-scan simulation complete.")
    print("[ATTACK] Logs inserted into database.")


def simulate_account_compromise(
    username="admin",
    ip_address="203.0.113.50",
    failed_attempts=10
):

    print("[ATTACK] Starting account-compromise simulation...")
    print(f"[ATTACK] Target user: {username}")
    print(f"[ATTACK] Source IP: {ip_address}")
    print(f"[ATTACK] Failed attempts: {failed_attempts}")
    print()

    for attempt in range(1, failed_attempts + 1):

        timestamp = datetime.now().isoformat()

        insert_event(
            timestamp=timestamp,
            event_type="LOGIN_FAILED",
            username=username,
            ip_address=ip_address
        )

        print(
            f"[ATTACK] Failed login "
            f"{attempt}/{failed_attempts}"
        )

    timestamp = datetime.now().isoformat()

    insert_event(
        timestamp=timestamp,
        event_type="LOGIN_SUCCESS",
        username=username,
        ip_address=ip_address
    )

    print()
    print("[ATTACK] Successful login after failed attempts.")
    print("[ATTACK] Possible account compromise!")
    print("[ATTACK] Logs inserted into database.")


if __name__ == "__main__":

    simulate_brute_force(
        username="admin",
        ip_address="203.0.113.50",
        attempts=10
    )

    print()

    simulate_port_scan(
        username="scanner",
        ip_address="198.51.100.25",
        ports=20
    )

    print()

    simulate_account_compromise(
        username="compromised_user",
        ip_address="192.0.2.100",
        failed_attempts=10
    )