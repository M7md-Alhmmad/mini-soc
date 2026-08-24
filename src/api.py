import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, StrictBool

from src.database import (
    get_events,
    get_incidents,
    get_incident,
    get_incident_history,
    get_incident_response_actions,
    RESPONSE_ACTIONS,
    set_incident_response_action,
    update_incident_status,
    update_incident_note
)


app = FastAPI(
    title="Mini SOC API",
    description="Security Operations Center backend",
    version="1.1.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "MINI_SOC_CORS_ORIGINS",
            "http://127.0.0.1:8000,http://localhost:8000"
        ).split(",")
        if origin.strip()
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)


class StatusUpdate(BaseModel):
    status: str


class NoteUpdate(BaseModel):
    note: str


class ResponseActionUpdate(BaseModel):
    completed: StrictBool


FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@app.get("/")
def home():

    return {
        "message": "Mini SOC API is running",
        "dashboard": "/dashboard",
        "documentation": "/docs"
    }


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return RedirectResponse(url="/ui/")


@app.get("/events")
def get_all_events():

    events = get_events()

    return {
        "total": len(events),
        "events": events
    }


@app.get("/incidents")
def get_all_incidents():

    incidents = get_incidents()

    return {
        "total": len(incidents),
        "incidents": incidents
    }


@app.get("/incidents/{incident_id}")
def get_single_incident(
    incident_id: int
):

    incident = get_incident(
        incident_id
    )

    if incident is None:

        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return {
        "id": incident[0],
        "type": incident[1],
        "severity": incident[2],
        "username": incident[3],
        "ip_address": incident[4],
        "failed_attempts": incident[5],
        "timestamp": incident[6],
        "status": incident[7],
        "mitre_technique": incident[8],
        "analyst_note": incident[9],
        "risk_score": incident[10]
    }


@app.get("/incidents/{incident_id}/history")
def get_history(
    incident_id: int
):

    incident = get_incident(
        incident_id
    )

    if incident is None:

        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    history = get_incident_history(
        incident_id
    )

    formatted_history = []

    for entry in history:

        formatted_history.append({
            "id": entry[0],
            "incident_id": entry[1],
            "action": entry[2],
            "details": entry[3],
            "timestamp": entry[4]
        })

    return {
        "incident_id": incident_id,
        "total": len(formatted_history),
        "history": formatted_history
    }


@app.get("/incidents/{incident_id}/response-actions")
def get_response_actions(
    incident_id: int
):

    if get_incident(incident_id) is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    actions = get_incident_response_actions(
        incident_id
    )

    return {
        "incident_id": incident_id,
        "total": len(actions),
        "actions": actions
    }


@app.patch("/incidents/{incident_id}/response-actions/{action_type}")
def change_response_action(
    incident_id: int,
    action_type: str,
    update: ResponseActionUpdate
):

    if get_incident(incident_id) is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    normalized_action_type = (
        action_type.strip().upper()
    )

    if normalized_action_type not in RESPONSE_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail="Invalid response action type"
        )

    action = set_incident_response_action(
        incident_id,
        normalized_action_type,
        update.completed
    )

    return {
        "message": (
            "Response action updated"
            if action["changed"]
            else "Response action unchanged"
        ),
        "incident_id": incident_id,
        "action": action
    }


@app.patch("/incidents/{incident_id}/status")
def change_incident_status(
    incident_id: int,
    update: StatusUpdate
):

    incident = get_incident(
        incident_id
    )

    if incident is None:

        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    allowed_statuses = {
        "OPEN",
        "INVESTIGATING",
        "RESOLVED"
    }

    normalized_status = update.status.strip().upper()

    if normalized_status not in allowed_statuses:

        raise HTTPException(
            status_code=400,
            detail="Invalid status"
        )

    update_incident_status(
        incident_id,
        normalized_status
    )

    return {
        "message": "Incident status updated",
        "incident_id": incident_id,
        "status": normalized_status
    }


@app.patch("/incidents/{incident_id}/note")
def change_incident_note(
    incident_id: int,
    update: NoteUpdate
):

    incident = get_incident(
        incident_id
    )

    if incident is None:

        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    update_incident_note(
        incident_id,
        update.note
    )

    return {
        "message": "Analyst note updated",
        "incident_id": incident_id
    }


@app.get("/stats")
def get_stats():

    events = get_events()
    incidents = get_incidents()

    return {
        "total_events": len(events),

        "total_incidents": len(incidents),

        "status": {

            "open": sum(
                1
                for incident in incidents
                if incident[7] == "OPEN"
            ),

            "investigating": sum(
                1
                for incident in incidents
                if incident[7] == "INVESTIGATING"
            ),

            "resolved": sum(
                1
                for incident in incidents
                if incident[7] == "RESOLVED"
            )
        },

        "severity": {

            "critical": sum(
                1
                for incident in incidents
                if incident[2] == "CRITICAL"
            ),

            "high": sum(
                1
                for incident in incidents
                if incident[2] == "HIGH"
            ),

            "medium": sum(
                1
                for incident in incidents
                if incident[2] == "MEDIUM"
            ),

            "low": sum(
                1
                for incident in incidents
                if incident[2] == "LOW"
            )
        }
    }


app.mount(
    "/ui",
    StaticFiles(directory=FRONTEND_DIR, html=True),
    name="frontend"
)
