import time

from .database import (
    get_events_after_id,
    get_or_create_monitor_checkpoint,
    update_monitor_checkpoint,
)
from .detection_engine import run_detection

CHECK_INTERVAL = 3


def process_event_batch(events, detector=None):
    """Process one event batch and persist its checkpoint on success."""
    if not events:
        return None

    detection_runner = detector or run_detection
    detection_runner(events)

    latest_event_id = events[-1][0]
    # Advance only after detection completes so failed batches can be retried.
    update_monitor_checkpoint(latest_event_id)
    return latest_event_id


def monitor_soc():
    print("\n" + "=" * 60)
    print("MINI SOC - LIVE SECURITY MONITOR")
    print("=" * 60)
    print(f"\n[SOC] Monitoring every {CHECK_INTERVAL} seconds.")
    print("[SOC] Incremental event processing enabled.")
    print("[SOC] Press CTRL+C to stop.\n")

    last_event_id = get_or_create_monitor_checkpoint()
    print(f"[SOC] Starting checkpoint: event #{last_event_id}")
    print("[SOC] Waiting for new events...\n")

    try:
        while True:
            time.sleep(CHECK_INTERVAL)
            new_events = get_events_after_id(last_event_id)

            if not new_events:
                print("[SOC] No new events.")
                continue

            first_event_id = new_events[0][0]
            latest_event_id = new_events[-1][0]

            print("\n" + "-" * 60)
            print(f"[SOC] {len(new_events)} new event(s) detected.")
            print(f"[SOC] Processing event IDs {first_event_id} -> {latest_event_id}\n")

            try:
                last_event_id = process_event_batch(new_events)
            except Exception as error:
                print(f"[SOC] Detection failed: {error}")
                print("[SOC] Checkpoint unchanged; batch will be retried.")
                print("-" * 60 + "\n")
                continue

            print(f"\n[SOC] Checkpoint updated: event #{last_event_id}")
            print("[SOC] Waiting for new events...")
            print("-" * 60 + "\n")
    except KeyboardInterrupt:
        print("\n\n" + "=" * 60)
        print("[SOC] Live monitoring stopped.")
        print("=" * 60 + "\n")


if __name__ == "__main__":
    monitor_soc()
