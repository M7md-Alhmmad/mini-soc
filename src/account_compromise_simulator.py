from datetime import datetime, timedelta

from .database import insert_event


def simulate_account_compromise():
    username = "admin"
    ip_address = "198.51.100.25"

    start_time = datetime.now()

    for attempt in range(5):
        timestamp = start_time + timedelta(seconds=attempt * 10)

        insert_event(
            timestamp.isoformat(),
            "LOGIN_FAILED",
            username,
            ip_address
        )

    success_time = start_time + timedelta(seconds=60)

    insert_event(
        success_time.isoformat(),
        "LOGIN_SUCCESS",
        username,
        ip_address
    )

    print("Account compromise scenario simulated.")


if __name__ == "__main__":
    simulate_account_compromise()
