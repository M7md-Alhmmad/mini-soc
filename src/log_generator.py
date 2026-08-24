from datetime import datetime, timedelta
from pathlib import Path
import random

from .database import insert_event


users = ["admin", "john", "sarah", "mohammed"]

ip_addresses = [
    "192.168.1.25",
    "192.168.1.42",
    "10.0.0.15",
    "10.0.0.23"
]

event_types = [
    "LOGIN_SUCCESS",
    "LOGIN_SUCCESS",
    "LOGIN_SUCCESS",
    "LOGIN_FAILED",
    "LOGIN_FAILED",
    "FILE_ACCESSED",
    "FILE_ACCESSED",
    "LOGOUT",
    "PASSWORD_CHANGED",
    "ACCOUNT_LOCKED",
    "PERMISSION_CHANGED",
    "FILE_DELETED"
]


def generate_logs(number_of_events=25):
    start_time = datetime.now()

    log_path = Path(__file__).resolve().parent.parent / "logs" / "security.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with log_path.open("a", encoding="utf-8") as log_file:

        current_time = start_time

        for _ in range(number_of_events):
            username = random.choice(users)
            ip_address = random.choice(ip_addresses)
            event_type = random.choice(event_types)

            current_time += timedelta(
                seconds=random.randint(1, 10)
            )

            timestamp = current_time

            event = (
                f"[{timestamp}] "
                f"{event_type} | "
                f"user={username} | "
                f"ip={ip_address}"
            )

            print(event)
            log_file.write(event + "\n")

            insert_event(
                timestamp.isoformat(),
                event_type,
                username,
                ip_address
            )


if __name__ == "__main__":
    generate_logs()
