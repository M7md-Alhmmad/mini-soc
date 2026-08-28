import os
import sqlite3
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = Path(os.getenv("MINI_SOC_DATABASE", DATA_DIR / "security_events.db"))
DEFAULT_MONITOR_STATE_KEY = "default_monitor"

RESPONSE_ACTIONS = {
    "DISABLE_ACCOUNT": {
        "label": "Disable account",
        "completed_details": "Account disabled",
        "reopened_details": "Account-disable action reopened",
    },
    "RESET_PASSWORD": {
        "label": "Reset password",
        "completed_details": "Password reset",
        "reopened_details": "Password-reset action reopened",
    },
    "BLOCK_IP": {
        "label": "Block attacker IP",
        "completed_details": "Attacker IP blocked",
        "reopened_details": "IP-block action reopened",
    },
    "REVOKE_SESSIONS": {
        "label": "Revoke active sessions",
        "completed_details": "Active sessions revoked",
        "reopened_details": "Session-revocation action reopened",
    },
    "ISOLATE_ENDPOINT": {
        "label": "Isolate endpoint",
        "completed_details": "Endpoint isolated",
        "reopened_details": "Endpoint-isolation action reopened",
    },
    "COLLECT_EVIDENCE": {
        "label": "Collect evidence",
        "completed_details": "Evidence collected",
        "reopened_details": "Evidence-collection action reopened",
    },
}


def get_connection():

    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH, timeout=10)

    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")

    return connection


def create_tables():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT,
            ip_address TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT DEFAULT 'OPEN',
            mitre_technique TEXT,
            analyst_note TEXT DEFAULT '',
            risk_score INTEGER DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT DEFAULT '',
            timestamp TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_response_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            action_type TEXT NOT NULL CHECK (
                action_type IN (
                    'DISABLE_ACCOUNT',
                    'RESET_PASSWORD',
                    'BLOCK_IP',
                    'REVOKE_SESSIONS',
                    'ISOLATE_ENDPOINT',
                    'COLLECT_EVIDENCE'
                )
            ),
            completed INTEGER NOT NULL DEFAULT 0 CHECK (completed IN (0, 1)),
            completed_at TEXT,
            UNIQUE (incident_id, action_type),
            FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS monitor_state (
            state_key TEXT PRIMARY KEY,
            last_processed_event_id INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        PRAGMA table_info(incidents)
    """)

    columns = [row[1] for row in cursor.fetchall()]

    if "risk_score" not in columns:
        cursor.execute("""
            ALTER TABLE incidents
            ADD COLUMN risk_score INTEGER DEFAULT 0
        """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_timestamp
        ON events(timestamp)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_incidents_identity
        ON incidents(incident_type, username, ip_address, timestamp)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_history_incident
        ON incident_history(incident_id, id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_response_actions_incident
        ON incident_response_actions(incident_id, action_type)
    """)

    connection.commit()
    connection.close()


def insert_event(timestamp, event_type, username, ip_address):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO events (
            timestamp,
            event_type,
            username,
            ip_address
        )
        VALUES (?, ?, ?, ?)
    """,
        (timestamp, event_type, username, ip_address),
    )

    connection.commit()
    connection.close()


def get_events():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            event_type,
            username,
            ip_address
        FROM events
        ORDER BY id DESC
    """)

    events = cursor.fetchall()

    connection.close()

    return events


def get_events_after_id(event_id):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            timestamp,
            event_type,
            username,
            ip_address
        FROM events
        WHERE id > ?
        ORDER BY id ASC
    """,
        (event_id,),
    )

    events = cursor.fetchall()

    connection.close()

    return events


def get_events_between(start_timestamp, end_timestamp):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            timestamp,
            event_type,
            username,
            ip_address
        FROM events
        WHERE timestamp >= ? AND timestamp <= ?
        ORDER BY timestamp ASC, id ASC
    """,
        (start_timestamp, end_timestamp),
    )

    events = cursor.fetchall()
    connection.close()

    return events


def get_latest_event_id():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT MAX(id)
        FROM events
    """)

    result = cursor.fetchone()

    connection.close()

    if result is None or result[0] is None:
        return 0

    return result[0]


def get_monitor_checkpoint(state_key=DEFAULT_MONITOR_STATE_KEY):
    connection = get_connection()
    row = connection.execute(
        """
        SELECT last_processed_event_id
        FROM monitor_state
        WHERE state_key = ?
        """,
        (state_key,),
    ).fetchone()
    connection.close()
    return row[0] if row else None


def get_or_create_monitor_checkpoint(state_key=DEFAULT_MONITOR_STATE_KEY):
    connection = get_connection()
    connection.execute("BEGIN IMMEDIATE")

    row = connection.execute(
        """
        SELECT last_processed_event_id
        FROM monitor_state
        WHERE state_key = ?
        """,
        (state_key,),
    ).fetchone()

    if row is None:
        latest_event_id = connection.execute(
            "SELECT COALESCE(MAX(id), 0) FROM events"
        ).fetchone()[0]
        connection.execute(
            """
            INSERT INTO monitor_state (
                state_key,
                last_processed_event_id,
                updated_at
            )
            VALUES (?, ?, ?)
            """,
            (state_key, latest_event_id, datetime.now().isoformat()),
        )
        connection.commit()
        connection.close()
        return latest_event_id

    connection.commit()
    connection.close()
    return row[0]


def update_monitor_checkpoint(event_id, state_key=DEFAULT_MONITOR_STATE_KEY):
    connection = get_connection()
    connection.execute(
        """
        INSERT INTO monitor_state (
            state_key,
            last_processed_event_id,
            updated_at
        )
        VALUES (?, ?, ?)
        ON CONFLICT (state_key)
        DO UPDATE SET
            last_processed_event_id = excluded.last_processed_event_id,
            updated_at = excluded.updated_at
        """,
        (state_key, event_id, datetime.now().isoformat()),
    )
    connection.commit()
    connection.close()


def insert_incident(
    incident_type,
    severity,
    username,
    ip_address,
    failed_attempts,
    timestamp,
    mitre_technique,
    risk_score=0,
):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO incidents (
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
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            incident_type,
            severity,
            username,
            ip_address,
            failed_attempts,
            timestamp,
            "OPEN",
            mitre_technique,
            "",
            risk_score,
        ),
    )

    incident_id = cursor.lastrowid

    cursor.execute(
        """
        INSERT INTO incident_history (
            incident_id,
            action,
            details,
            timestamp
        )
        VALUES (?, ?, ?, ?)
    """,
        (
            incident_id,
            "INCIDENT_CREATED",
            f"{incident_type} incident detected",
            timestamp,
        ),
    )

    connection.commit()
    connection.close()

    return incident_id


def get_incidents():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
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
        FROM incidents
        ORDER BY id DESC
    """)

    incidents = cursor.fetchall()

    connection.close()

    return incidents


def get_incident(incident_id):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
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
        FROM incidents
        WHERE id = ?
    """,
        (incident_id,),
    )

    incident = cursor.fetchone()

    connection.close()

    return incident


def update_incident_status(incident_id, status):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT status
        FROM incidents
        WHERE id = ?
    """,
        (incident_id,),
    )

    result = cursor.fetchone()

    if result is None:
        connection.close()
        return False

    old_status = result[0]

    cursor.execute(
        """
        UPDATE incidents
        SET status = ?
        WHERE id = ?
    """,
        (status, incident_id),
    )

    timestamp = datetime.now().isoformat()

    cursor.execute(
        """
        INSERT INTO incident_history (
            incident_id,
            action,
            details,
            timestamp
        )
        VALUES (?, ?, ?, ?)
    """,
        (
            incident_id,
            "STATUS_CHANGED",
            f"Status changed from {old_status} to {status}",
            timestamp,
        ),
    )

    connection.commit()
    connection.close()

    return True


def update_incident_note(incident_id, note):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT analyst_note
        FROM incidents
        WHERE id = ?
    """,
        (incident_id,),
    )

    result = cursor.fetchone()

    if result is None:
        connection.close()
        return False

    cursor.execute(
        """
        UPDATE incidents
        SET analyst_note = ?
        WHERE id = ?
    """,
        (note, incident_id),
    )

    timestamp = datetime.now().isoformat()

    cursor.execute(
        """
        INSERT INTO incident_history (
            incident_id,
            action,
            details,
            timestamp
        )
        VALUES (?, ?, ?, ?)
    """,
        (incident_id, "ANALYST_NOTE_UPDATED", "Analyst note updated", timestamp),
    )

    connection.commit()
    connection.close()

    return True


def get_incident_history(incident_id):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            incident_id,
            action,
            details,
            timestamp
        FROM incident_history
        WHERE incident_id = ?
        ORDER BY id ASC
    """,
        (incident_id,),
    )

    history = cursor.fetchall()

    connection.close()

    return history


def get_incident_response_actions(incident_id):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            action_type,
            completed,
            completed_at
        FROM incident_response_actions
        WHERE incident_id = ?
    """,
        (incident_id,),
    )

    stored_actions = {row[0]: row for row in cursor.fetchall()}

    connection.close()

    actions = []

    for action_type, metadata in RESPONSE_ACTIONS.items():
        stored = stored_actions.get(action_type)

        actions.append(
            {
                "action_type": action_type,
                "label": metadata["label"],
                "completed": bool(stored[1]) if stored else False,
                "completed_at": stored[2] if stored else None,
            }
        )

    return actions


def set_incident_response_action(incident_id, action_type, completed):

    if action_type not in RESPONSE_ACTIONS:
        raise ValueError("Invalid response action type")

    connection = get_connection()
    cursor = connection.cursor()

    connection.execute("BEGIN IMMEDIATE")

    cursor.execute(
        """
        SELECT id
        FROM incidents
        WHERE id = ?
    """,
        (incident_id,),
    )

    if cursor.fetchone() is None:
        connection.close()
        return None

    cursor.execute(
        """
        SELECT completed, completed_at
        FROM incident_response_actions
        WHERE incident_id = ? AND action_type = ?
    """,
        (incident_id, action_type),
    )

    existing = cursor.fetchone()
    previous_completed = bool(existing[0]) if existing else False

    if previous_completed == completed:
        connection.close()
        return {
            "action_type": action_type,
            "label": RESPONSE_ACTIONS[action_type]["label"],
            "completed": previous_completed,
            "completed_at": existing[1] if existing else None,
            "changed": False,
        }

    timestamp = datetime.now().isoformat()
    completed_at = timestamp if completed else None

    cursor.execute(
        """
        INSERT INTO incident_response_actions (
            incident_id,
            action_type,
            completed,
            completed_at
        )
        VALUES (?, ?, ?, ?)
        ON CONFLICT (incident_id, action_type)
        DO UPDATE SET
            completed = excluded.completed,
            completed_at = excluded.completed_at
    """,
        (incident_id, action_type, int(completed), completed_at),
    )

    history_action = (
        "RESPONSE_ACTION_COMPLETED" if completed else "RESPONSE_ACTION_REOPENED"
    )

    details_key = "completed_details" if completed else "reopened_details"

    cursor.execute(
        """
        INSERT INTO incident_history (
            incident_id,
            action,
            details,
            timestamp
        )
        VALUES (?, ?, ?, ?)
    """,
        (
            incident_id,
            history_action,
            RESPONSE_ACTIONS[action_type][details_key],
            timestamp,
        ),
    )

    connection.commit()
    connection.close()

    return {
        "action_type": action_type,
        "label": RESPONSE_ACTIONS[action_type]["label"],
        "completed": completed,
        "completed_at": completed_at,
        "changed": True,
    }


create_tables()
