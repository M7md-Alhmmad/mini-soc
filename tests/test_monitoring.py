import os
import subprocess
import sys
from datetime import datetime, timedelta

import pytest

from src import database
from src.main import process_event_batch


def add_event(at, event_type="LOGIN_SUCCESS", username="alice"):
    database.insert_event(at.isoformat(), event_type, username, "203.0.113.20")


def test_checkpoint_recovers_offline_events(isolated_database):
    start = datetime(2026, 1, 1, 12, 0, 0)
    assert database.get_or_create_monitor_checkpoint() == 0

    add_event(start)
    add_event(start + timedelta(seconds=10))

    processed_batches = []
    first_batch = database.get_events_after_id(0)
    checkpoint = process_event_batch(
        first_batch,
        detector=lambda events: processed_batches.append(
            [event[0] for event in events]
        ),
    )

    assert checkpoint == 2
    assert database.get_monitor_checkpoint() == 2
    assert processed_batches == [[1, 2]]

    for offset in range(5):
        add_event(
            start + timedelta(minutes=1, seconds=offset * 10),
            "LOGIN_FAILED",
            username="offline-user",
        )

    restarted_checkpoint = database.get_or_create_monitor_checkpoint()
    offline_events = database.get_events_after_id(restarted_checkpoint)
    assert [event[0] for event in offline_events] == [3, 4, 5, 6, 7]

    checkpoint = process_event_batch(offline_events)
    assert checkpoint == 7
    assert database.get_monitor_checkpoint() == 7
    assert database.get_events_after_id(checkpoint) == []
    assert [incident[1] for incident in database.get_incidents()] == ["BRUTE_FORCE"]
    assert (
        process_event_batch(
            [], detector=lambda events: processed_batches.append(events)
        )
        is None
    )
    assert processed_batches == [[1, 2]]


def test_first_run_starts_at_current_latest_event(isolated_database):
    start = datetime(2026, 1, 1, 12, 0, 0)
    for offset in range(3):
        add_event(start + timedelta(seconds=offset))

    assert database.get_or_create_monitor_checkpoint() == 3
    assert database.get_events_after_id(3) == []


def test_failed_detection_does_not_advance_checkpoint(isolated_database):
    start = datetime(2026, 1, 1, 12, 0, 0)
    assert database.get_or_create_monitor_checkpoint() == 0
    add_event(start, "LOGIN_FAILED")
    pending_events = database.get_events_after_id(0)

    def fail_detection(_events):
        raise RuntimeError("simulated detection failure")

    with pytest.raises(RuntimeError, match="simulated detection failure"):
        process_event_batch(pending_events, detector=fail_detection)

    assert database.get_monitor_checkpoint() == 0
    assert database.get_events_after_id(0) == pending_events

    assert process_event_batch(pending_events, detector=lambda _events: None) == 1
    assert database.get_monitor_checkpoint() == 1


def test_checkpoint_survives_new_python_process(isolated_database):
    assert database.get_or_create_monitor_checkpoint() == 0
    database.update_monitor_checkpoint(42)

    environment = os.environ.copy()
    environment["MINI_SOC_DATABASE"] = str(isolated_database)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from src.database import get_monitor_checkpoint; "
                "print(get_monitor_checkpoint())"
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.stdout.strip() == "42"
