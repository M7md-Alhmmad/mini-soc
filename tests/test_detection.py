from datetime import datetime, timedelta

from src import database
from src.detection_engine import (
    calculate_risk_score,
    detect_port_scan,
    run_detection,
)


def add_event(at, event_type, username="alice", ip_address="203.0.113.10"):
    database.insert_event(at.isoformat(), event_type, username, ip_address)


def port_scan_events(count, spacing_seconds=10):
    start = datetime(2026, 1, 1, 12, 0, 0)
    return [
        (
            index + 1,
            (start + timedelta(seconds=index * spacing_seconds)).isoformat(),
            "PORT_SCAN",
            "scanner",
            "198.51.100.25",
        )
        for index in range(count)
    ]


def test_risk_score_is_bounded():
    assert calculate_risk_score("LOW") == 25
    assert calculate_risk_score("HIGH", 5) == 80
    assert calculate_risk_score("CRITICAL", 10) == 100


def test_incremental_detection_uses_prior_context(isolated_database):
    start = datetime(2026, 1, 1, 12, 0, 0)
    for offset in range(4):
        add_event(start + timedelta(seconds=offset * 20), "LOGIN_FAILED")

    final_time = start + timedelta(seconds=80)
    add_event(final_time, "LOGIN_FAILED")
    newest_event = database.get_events_after_id(4)

    run_detection(newest_event)

    incidents = database.get_incidents()
    assert len(incidents) == 1
    assert incidents[0][1] == "BRUTE_FORCE"
    assert incidents[0][5] == 5


def test_failures_then_success_correlate_to_compromise(isolated_database):
    start = datetime(2026, 1, 1, 12, 0, 0)
    for offset in range(5):
        add_event(start + timedelta(seconds=offset * 10), "LOGIN_FAILED")
    add_event(start + timedelta(seconds=60), "LOGIN_SUCCESS")

    run_detection()

    incidents = database.get_incidents()
    assert [incident[1] for incident in incidents] == ["ACCOUNT_COMPROMISE"]
    assert incidents[0][2] == "CRITICAL"
    assert incidents[0][10] == 95


def test_port_scan_must_fit_in_five_minute_window(isolated_database):
    start = datetime(2026, 1, 1, 12, 0, 0)
    for offset in range(10):
        add_event(
            start + timedelta(seconds=offset * 40), "PORT_SCAN", username="scanner"
        )

    run_detection()
    assert database.get_incidents() == []

    for offset in range(10):
        add_event(
            start + timedelta(hours=1, seconds=offset * 10),
            "PORT_SCAN",
            username="scanner",
        )

    run_detection()
    assert database.get_incidents()[0][1] == "PORT_SCAN"


def test_port_scan_detects_normal_valid_window():
    alerts = detect_port_scan(port_scan_events(10))

    assert len(alerts) == 1
    assert alerts[0]["type"] == "PORT_SCAN"
    assert alerts[0]["failed_attempts"] == 10
    assert alerts[0]["risk_score"] == 85
    assert alerts[0]["mitre_technique"] == "T1046"


def test_port_scan_survives_trailing_stale_event():
    events = port_scan_events(10)
    stale_timestamp = datetime(2026, 1, 1, 12, 10, 0).isoformat()
    events.append((11, stale_timestamp, "PORT_SCAN", "scanner", "198.51.100.25"))

    alerts = detect_port_scan(events)

    assert len(alerts) == 1
    assert alerts[0]["failed_attempts"] == 10
    assert alerts[0]["timestamp"] == events[9][1]


def test_port_scan_below_threshold_is_not_detected():
    assert detect_port_scan(port_scan_events(9)) == []


def test_port_scan_spread_outside_window_is_not_detected():
    assert detect_port_scan(port_scan_events(10, spacing_seconds=40)) == []


def test_port_scan_more_than_threshold_uses_full_window():
    alerts = detect_port_scan(port_scan_events(20))

    assert len(alerts) == 1
    assert alerts[0]["failed_attempts"] == 20
    assert alerts[0]["risk_score"] == 85


def test_incremental_port_scan_uses_prior_context(isolated_database):
    start = datetime(2026, 1, 1, 12, 0, 0)
    for offset in range(8):
        add_event(
            start + timedelta(seconds=offset * 10),
            "PORT_SCAN",
            username="scanner",
            ip_address="198.51.100.25",
        )

    run_detection(database.get_events_after_id(0))
    assert database.get_incidents() == []

    for offset in range(8, 10):
        add_event(
            start + timedelta(seconds=offset * 10),
            "PORT_SCAN",
            username="scanner",
            ip_address="198.51.100.25",
        )

    run_detection(database.get_events_after_id(8))
    incidents = database.get_incidents()
    assert len(incidents) == 1
    assert incidents[0][1] == "PORT_SCAN"
    assert incidents[0][5] == 10
