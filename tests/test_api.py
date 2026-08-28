from datetime import datetime

from fastapi.testclient import TestClient

from src import database
from src.api import app


def test_dashboard_and_empty_stats(isolated_database):
    client = TestClient(app)

    response = client.get("/stats")
    assert response.status_code == 200
    assert response.json()["total_events"] == 0

    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/ui/"
    assert client.get("/ui/").status_code == 200


def test_incident_workflow_records_history(isolated_database):
    incident_id = database.insert_incident(
        "BRUTE_FORCE",
        "HIGH",
        "alice",
        "203.0.113.10",
        7,
        "2026-01-01T12:00:00",
        "T1110",
        80,
    )
    client = TestClient(app)

    response = client.patch(
        f"/incidents/{incident_id}/status", json={"status": "investigating"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "INVESTIGATING"

    response = client.patch(
        f"/incidents/{incident_id}/note",
        json={"note": "Source blocked and credentials reset."},
    )
    assert response.status_code == 200

    incident = client.get(f"/incidents/{incident_id}").json()
    assert incident["analyst_note"] == "Source blocked and credentials reset."

    history = client.get(f"/incidents/{incident_id}/history").json()["history"]
    assert [entry["action"] for entry in history] == [
        "INCIDENT_CREATED",
        "STATUS_CHANGED",
        "ANALYST_NOTE_UPDATED",
    ]


def test_invalid_status_and_missing_incident(isolated_database):
    client = TestClient(app)
    assert (
        client.patch("/incidents/999/status", json={"status": "OPEN"}).status_code
        == 404
    )

    incident_id = database.insert_incident(
        "PORT_SCAN",
        "HIGH",
        "scanner",
        "198.51.100.2",
        10,
        "2026-01-01T12:00:00",
        "T1046",
        85,
    )
    assert (
        client.patch(
            f"/incidents/{incident_id}/status", json={"status": "CLOSED"}
        ).status_code
        == 400
    )


def test_response_action_lifecycle_and_history(isolated_database):
    incident_id = database.insert_incident(
        "ACCOUNT_COMPROMISE",
        "CRITICAL",
        "alice",
        "203.0.113.10",
        6,
        "2026-01-01T12:00:00",
        "T1078",
        95,
    )
    client = TestClient(app)

    initial = client.get(f"/incidents/{incident_id}/response-actions")
    assert initial.status_code == 200
    assert initial.json()["total"] == 6
    assert all(
        not action["completed"] and action["completed_at"] is None
        for action in initial.json()["actions"]
    )

    completed = client.patch(
        f"/incidents/{incident_id}/response-actions/BLOCK_IP", json={"completed": True}
    )
    assert completed.status_code == 200
    completed_action = completed.json()["action"]
    assert completed_action["completed"] is True
    assert completed_action["changed"] is True
    assert datetime.fromisoformat(completed_action["completed_at"])

    persisted = client.get(f"/incidents/{incident_id}/response-actions").json()[
        "actions"
    ]
    blocked_ip = next(
        action for action in persisted if action["action_type"] == "BLOCK_IP"
    )
    assert blocked_ip["completed"] is True
    assert blocked_ip["completed_at"] == completed_action["completed_at"]

    history_url = f"/incidents/{incident_id}/history"
    history_before_repeat = client.get(history_url).json()["history"]
    assert history_before_repeat[-1]["action"] == "RESPONSE_ACTION_COMPLETED"
    assert history_before_repeat[-1]["details"] == "Attacker IP blocked"

    repeated = client.patch(
        f"/incidents/{incident_id}/response-actions/BLOCK_IP", json={"completed": True}
    )
    assert repeated.status_code == 200
    assert repeated.json()["action"]["changed"] is False
    assert len(client.get(history_url).json()["history"]) == len(history_before_repeat)

    connection = database.get_connection()
    stored_rows = connection.execute(
        """
        SELECT completed, completed_at
        FROM incident_response_actions
        WHERE incident_id = ? AND action_type = ?
        """,
        (incident_id, "BLOCK_IP"),
    ).fetchall()
    connection.close()
    assert stored_rows == [(1, completed_action["completed_at"])]

    reopened = client.patch(
        f"/incidents/{incident_id}/response-actions/BLOCK_IP", json={"completed": False}
    )
    assert reopened.status_code == 200
    assert reopened.json()["action"]["completed"] is False
    assert reopened.json()["action"]["completed_at"] is None

    final_history = client.get(history_url).json()["history"]
    assert final_history[-1]["action"] == "RESPONSE_ACTION_REOPENED"
    assert final_history[-1]["details"] == "IP-block action reopened"


def test_response_action_validation(isolated_database):
    incident_id = database.insert_incident(
        "PORT_SCAN",
        "HIGH",
        "scanner",
        "198.51.100.2",
        10,
        "2026-01-01T12:00:00",
        "T1046",
        85,
    )
    client = TestClient(app)

    assert client.get("/incidents/999/response-actions").status_code == 404
    assert (
        client.patch(
            "/incidents/999/response-actions/BLOCK_IP", json={"completed": True}
        ).status_code
        == 404
    )
    assert (
        client.patch(
            f"/incidents/{incident_id}/response-actions/DELETE_EVIDENCE",
            json={"completed": True},
        ).status_code
        == 400
    )
    assert (
        client.patch(
            f"/incidents/{incident_id}/response-actions/BLOCK_IP",
            json={"completed": "yes"},
        ).status_code
        == 422
    )
