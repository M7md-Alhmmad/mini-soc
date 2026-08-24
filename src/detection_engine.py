from datetime import datetime, timedelta, timezone

from .database import (
    get_events,
    get_events_between,
    get_incidents,
    insert_incident
)


DETECTION_WINDOW_SECONDS = 300
INCIDENT_DEDUP_SECONDS = 300


def parse_timestamp(value):
    """Parse ISO timestamps, accepting both naive and timezone-aware values."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


# =========================================================
# RISK SCORING
# =========================================================

def calculate_risk_score(
    severity,
    failed_attempts=0
):

    severity_scores = {
        "LOW": 25,
        "MEDIUM": 50,
        "HIGH": 75,
        "CRITICAL": 90
    }

    score = severity_scores.get(
        severity,
        25
    )

    if failed_attempts >= 10:
        score += 10

    elif failed_attempts >= 5:
        score += 5

    return min(
        score,
        100
    )


# =========================================================
# BRUTE FORCE DETECTION
# =========================================================

def detect_brute_force(
    events
):

    alerts = []
    login_failures = {}

    for event in events:

        event_type = event[2]
        username = event[3]
        ip_address = event[4]

        if event_type != "LOGIN_FAILED":
            continue

        if not username or not ip_address:
            continue

        key = (
            username,
            ip_address
        )

        if key not in login_failures:
            login_failures[key] = []

        login_failures[key].append(
            event
        )


    for key, failed_events in login_failures.items():

        failed_events = sorted(
            failed_events,
            key=lambda event: event[1]
        )

        detected_events = []

        for event in failed_events:

            current_time = parse_timestamp(
                event[1]
            )

            window_start = (
                current_time.timestamp()
                - 300
            )

            recent_events = []

            for previous_event in failed_events:

                previous_time = parse_timestamp(
                    previous_event[1]
                )

                if (
                    previous_time.timestamp()
                    >= window_start
                    and
                    previous_time.timestamp()
                    <= current_time.timestamp()
                ):

                    recent_events.append(
                        previous_event
                    )

            if len(recent_events) >= 5:

                detected_events = (
                    recent_events
                )


        if detected_events:

            username, ip_address = key

            failed_attempts = len(
                detected_events
            )

            severity = "HIGH"

            risk_score = calculate_risk_score(
                severity,
                failed_attempts
            )

            latest_event = (
                detected_events[-1]
            )

            alerts.append({
                "type": "BRUTE_FORCE",
                "severity": severity,
                "username": username,
                "ip_address": ip_address,
                "failed_attempts": failed_attempts,
                "timestamp": latest_event[1],
                "mitre_technique": "T1110",
                "risk_score": risk_score
            })


    return alerts


# =========================================================
# PORT SCAN DETECTION
# =========================================================

def detect_port_scan(
    events
):

    alerts = []
    port_scans = {}

    for event in events:

        event_type = event[2]
        username = event[3]
        ip_address = event[4]

        if event_type != "PORT_SCAN":
            continue

        if not username or not ip_address:
            continue

        key = (
            username,
            ip_address
        )

        if key not in port_scans:
            port_scans[key] = []

        port_scans[key].append(
            event
        )


    for key, scan_events in port_scans.items():
        scan_events = sorted(
            scan_events,
            key=lambda event: parse_timestamp(event[1])
        )
        event_times = [parse_timestamp(event[1]) for event in scan_events]

        left = 0
        detected_events = []

        for right, current_time in enumerate(event_times):
            while (
                current_time - event_times[left]
            ).total_seconds() > DETECTION_WINDOW_SECONDS:
                left += 1

            if right - left + 1 >= 10:
                # Keep the most recent qualifying window; later stale events
                # must not erase a detection that already met the threshold.
                detected_events = scan_events[left:right + 1]

        if len(detected_events) < 10:
            continue

        username, ip_address = key

        scan_count = len(
            detected_events
        )

        severity = "HIGH"

        risk_score = calculate_risk_score(
            severity,
            scan_count
        )

        latest_event = detected_events[-1]

        alerts.append({
            "type": "PORT_SCAN",
            "severity": severity,
            "username": username,
            "ip_address": ip_address,
            "failed_attempts": scan_count,
            "timestamp": latest_event[1],
            "mitre_technique": "T1046",
            "risk_score": risk_score
        })


    return alerts


# =========================================================
# SUSPICIOUS LOGIN DETECTION
# =========================================================

def detect_suspicious_login(
    events
):

    failed_logins = {}
    suspicious_alerts = {}

    sorted_events = sorted(
        events,
        key=lambda event: event[1]
    )

    for event in sorted_events:

        event_type = event[2]
        username = event[3]
        ip_address = event[4]

        if not username or not ip_address:
            continue

        key = (
            username,
            ip_address
        )


        if event_type == "LOGIN_FAILED":

            if key not in failed_logins:
                failed_logins[key] = []

            failed_logins[key].append(
                event
            )

            continue


        if event_type != "LOGIN_SUCCESS":
            continue

        if key not in failed_logins:
            continue


        success_time = parse_timestamp(
            event[1]
        )

        window_start = (
            success_time.timestamp()
            - 300
        )

        recent_failures = []

        for failed_event in failed_logins[key]:

            failed_time = parse_timestamp(
                failed_event[1]
            )

            if (
                failed_time.timestamp()
                >= window_start
                and
                failed_time.timestamp()
                <= success_time.timestamp()
            ):

                recent_failures.append(
                    failed_event
                )


        if len(recent_failures) >= 5:

            failed_attempts = len(
                recent_failures
            )

            severity = "CRITICAL"

            risk_score = calculate_risk_score(
                severity,
                failed_attempts
            )

            suspicious_alerts[key] = {
                "type": "SUSPICIOUS_LOGIN",
                "severity": severity,
                "username": username,
                "ip_address": ip_address,
                "failed_attempts": failed_attempts,
                "timestamp": event[1],
                "mitre_technique": "T1078",
                "risk_score": risk_score
            }


    return list(
        suspicious_alerts.values()
    )


# =========================================================
# ALERT CORRELATION
# =========================================================

def correlate_alerts(
    alerts
):

    correlated_alerts = []

    suspicious_logins = [
        alert
        for alert in alerts
        if alert["type"]
        == "SUSPICIOUS_LOGIN"
    ]


    for alert in alerts:

        if alert["type"] == "BRUTE_FORCE":

            matching_compromise = any(

                suspicious_alert["username"]
                == alert["username"]

                and

                suspicious_alert["ip_address"]
                == alert["ip_address"]

                for suspicious_alert
                in suspicious_logins
            )


            if matching_compromise:

                print(
                    f"[CORRELATION] "
                    f"BRUTE_FORCE + successful login | "
                    f"user={alert['username']} | "
                    f"ip={alert['ip_address']} "
                    f"-> ACCOUNT_COMPROMISE"
                )

                continue


        if (
            alert["type"]
            == "SUSPICIOUS_LOGIN"
        ):

            correlated_alert = (
                alert.copy()
            )

            correlated_alert["type"] = (
                "ACCOUNT_COMPROMISE"
            )

            correlated_alert["severity"] = (
                "CRITICAL"
            )

            correlated_alert["risk_score"] = (
                calculate_risk_score(
                    "CRITICAL",
                    alert[
                        "failed_attempts"
                    ]
                )
            )

            correlated_alert[
                "mitre_technique"
            ] = "T1078"

            correlated_alerts.append(
                correlated_alert
            )

            continue


        correlated_alerts.append(
            alert
        )


    return correlated_alerts


# =========================================================
# INCIDENT DEDUPLICATION
# =========================================================

def is_duplicate_incident(
    alert,
    incidents
):

    for incident in incidents:

        incident_type = (
            incident[1]
        )

        username = (
            incident[3]
        )

        ip_address = (
            incident[4]
        )

        if (
            incident_type
            == alert["type"]

            and

            username
            == alert["username"]

            and

            ip_address
            == alert["ip_address"]
        ):
            try:
                age = abs((
                    parse_timestamp(alert["timestamp"])
                    - parse_timestamp(incident[6])
                ).total_seconds())
            except (TypeError, ValueError):
                return True

            if age <= INCIDENT_DEDUP_SECONDS:
                return True


    return False


# =========================================================
# SAVE INCIDENTS
# =========================================================

def save_incidents(
    alerts
):

    incidents = get_incidents()

    new_incidents = 0
    duplicates = 0


    for alert in alerts:

        if is_duplicate_incident(
            alert,
            incidents
        ):

            print(
                f"[DEDUP] "
                f"Existing incident found | "
                f"{alert['type']} | "
                f"user={alert['username']} | "
                f"ip={alert['ip_address']}"
            )

            duplicates += 1

            continue


        insert_incident(
            alert["type"],
            alert["severity"],
            alert["username"],
            alert["ip_address"],
            alert["failed_attempts"],
            alert["timestamp"],
            alert["mitre_technique"],
            alert["risk_score"]
        )


        print(
            f"[INCIDENT] "
            f"{alert['type']} | "
            f"severity={alert['severity']} | "
            f"user={alert['username']} | "
            f"ip={alert['ip_address']} | "
            f"attempts={alert['failed_attempts']} | "
            f"risk={alert['risk_score']}/100"
        )


        incidents = get_incidents()

        new_incidents += 1


    print(
        f"[DETECTION] "
        f"New incidents: {new_incidents} | "
        f"Duplicates ignored: {duplicates}"
    )


# =========================================================
# RUN DETECTION ENGINE
# =========================================================

def run_detection(
    events=None
):

    if events is None:

        events = get_events()

        print(
            f"[DETECTION] Full scan mode | "
            f"{len(events)} event(s)"
        )

    else:

        print(
            f"[DETECTION] Incremental mode | "
            f"{len(events)} new event(s)"
        )

        if events:
            timestamps = [parse_timestamp(event[1]) for event in events]
            start = min(timestamps) - timedelta(seconds=DETECTION_WINDOW_SECONDS)
            end = max(timestamps)
            events = get_events_between(start.isoformat(), end.isoformat())

            print(
                f"[DETECTION] Context window | "
                f"{len(events)} event(s) analyzed"
            )


    if not events:

        print(
            "[DETECTION] "
            "No events to analyze."
        )

        return


    brute_force_alerts = (
        detect_brute_force(
            events
        )
    )


    port_scan_alerts = (
        detect_port_scan(
            events
        )
    )


    suspicious_login_alerts = (
        detect_suspicious_login(
            events
        )
    )


    raw_alerts = (
        brute_force_alerts
        + port_scan_alerts
        + suspicious_login_alerts
    )


    if not raw_alerts:

        print(
            "[DETECTION] "
            "No threats detected."
        )

        return


    print(
        f"[DETECTION] "
        f"{len(raw_alerts)} "
        f"raw alert(s) detected."
    )


    correlated_alerts = (
        correlate_alerts(
            raw_alerts
        )
    )


    print(
        f"[CORRELATION] "
        f"{len(correlated_alerts)} "
        f"incident(s) after correlation."
    )


    save_incidents(
        correlated_alerts
    )


if __name__ == "__main__":

    run_detection()
