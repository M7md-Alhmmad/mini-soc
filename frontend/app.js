const API_URL = window.location.protocol === "file:"
    ? "http://127.0.0.1:8000"
    : window.location.origin;

let allIncidents = [];


/* =========================================================
   LOAD STATISTICS
========================================================= */

async function loadStats() {

    const response = await fetch(
        `${API_URL}/stats`
    );

    if (!response.ok) {
        throw new Error(
            "Failed to load statistics"
        );
    }

    const data = await response.json();


    document.getElementById(
        "total-events"
    ).textContent =
        data.total_events;


    document.getElementById(
        "total-incidents"
    ).textContent =
        data.total_incidents;


    document.getElementById(
        "critical-incidents"
    ).textContent =
        data.severity.critical;


    document.getElementById(
        "open-incidents"
    ).textContent =
        data.status.open;


    document.getElementById(
        "status-open"
    ).textContent =
        data.status.open;


    document.getElementById(
        "status-investigating"
    ).textContent =
        data.status.investigating;


    document.getElementById(
        "status-resolved"
    ).textContent =
        data.status.resolved;


    document.getElementById(
        "severity-critical"
    ).textContent =
        data.severity.critical;


    document.getElementById(
        "severity-high"
    ).textContent =
        data.severity.high;


    document.getElementById(
        "severity-medium"
    ).textContent =
        data.severity.medium;


    document.getElementById(
        "severity-low"
    ).textContent =
        data.severity.low;
}


/* =========================================================
   UPDATE INCIDENT STATUS
========================================================= */

async function updateStatus(
    incidentId,
    status
) {

    try {
        const response = await fetch(
            `${API_URL}/incidents/${incidentId}/status`,
            {
            method: "PATCH",

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({
                status: status
            })
            }
        );


        if (!response.ok) {

        alert(
            "Failed to update incident status."
        );

            return;
        }


        await loadDashboard();
    } catch (error) {
        console.error(error);
        alert("Unable to connect to the SOC API.");
    }
}


/* =========================================================
   UPDATE ANALYST NOTE
========================================================= */

async function updateNote(
    incidentId
) {

    const noteInput =
        document.getElementById(
            `note-${incidentId}`
        );


    try {
        const response = await fetch(
            `${API_URL}/incidents/${incidentId}/note`,
            {
            method: "PATCH",

            headers: {
                "Content-Type":
                    "application/json"
            },

            body: JSON.stringify({
                note: noteInput.value
            })
            }
        );


        if (!response.ok) {

        alert(
            "Failed to update analyst note."
        );

            return;
        }


        await loadDashboard();
    } catch (error) {
        console.error(error);
        alert("Unable to connect to the SOC API.");
    }
}


/* =========================================================
   RISK SCORE
========================================================= */

function getRiskLevel(score) {

    if (score >= 80) {
        return "CRITICAL";
    }

    if (score >= 60) {
        return "HIGH";
    }

    if (score >= 30) {
        return "MEDIUM";
    }

    return "LOW";
}


/* =========================================================
   FORMAT TIMESTAMP
========================================================= */

function formatTimestamp(timestamp) {

    if (!timestamp) {
        return "Unknown time";
    }

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return timestamp;
    }

    return date.toLocaleString();
}


/* =========================================================
   ESCAPE HTML
========================================================= */

function escapeHTML(value) {

    if (
        value === null ||
        value === undefined
    ) {
        return "";
    }

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


/* =========================================================
   TIMELINE ACTION LABEL
========================================================= */

function getTimelineActionLabel(
    action
) {

    const labels = {

        INCIDENT_CREATED:
            "🚨 Incident Created",

        STATUS_CHANGED:
            "🔄 Status Changed",

        ANALYST_NOTE_UPDATED:
            "📝 Analyst Note Updated",

        RESPONSE_ACTION_COMPLETED:
            "🛡️ Response Action Completed",

        RESPONSE_ACTION_REOPENED:
            "↩️ Response Action Reopened"
    };


    return (
        labels[action] ||
        `⚡ ${action}`
    );
}


/* =========================================================
   RENDER INCIDENT HISTORY
========================================================= */

function renderIncidentHistory(
    history
) {

    if (
        !history ||
        history.length === 0
    ) {

        return `
            <div class="timeline-item">

                <span></span>

                <div>
                    <strong>
                        No recorded history yet
                    </strong>

                    <p>
                        This incident existed before
                        audit logging was enabled,
                        or no analyst actions have
                        been recorded yet.
                    </p>
                </div>

            </div>
        `;
    }


    return history
        .map(
            entry => {

                const action =
                    escapeHTML(
                        getTimelineActionLabel(
                            entry.action
                        )
                    );

                const details =
                    escapeHTML(
                        entry.details
                    );

                const timestamp =
                    escapeHTML(
                        formatTimestamp(
                            entry.timestamp
                        )
                    );


                return `
                    <div class="timeline-item">

                        <span></span>

                        <div>

                            <strong>
                                ${action}
                            </strong>

                            <p>
                                ${details}
                            </p>

                            <small>
                                ${timestamp}
                            </small>

                        </div>

                    </div>
                `;
            }
        )
        .join("");
}


/* =========================================================
   RESPONSE ACTIONS
========================================================= */

function renderResponseActions(
    actions,
    incidentId
) {

    if (!actions || actions.length === 0) {
        return `
            <p class="response-actions-empty">
                No response actions are available.
            </p>
        `;
    }

    return actions
        .map(action => {
            const actionType =
                escapeHTML(action.action_type);

            const label =
                escapeHTML(action.label);

            const completedAt = action.completed_at
                ? `Completed ${escapeHTML(
                    formatTimestamp(action.completed_at)
                )}`
                : "Not completed";

            return `
                <label class="response-action ${
                    action.completed ? "completed" : ""
                }">
                    <input
                        type="checkbox"
                        ${action.completed ? "checked" : ""}
                        aria-label="${label}"
                        onchange="updateResponseAction(
                            ${Number(incidentId)},
                            '${actionType}',
                            this
                        )"
                    >

                    <span class="response-action-copy">
                        <strong>${label}</strong>
                        <small>${completedAt}</small>
                    </span>
                </label>
            `;
        })
        .join("");
}


async function updateResponseAction(
    incidentId,
    actionType,
    checkbox
) {

    checkbox.disabled = true;

    try {
        const response = await fetch(
            `${API_URL}/incidents/${incidentId}/response-actions/${actionType}`,
            {
                method: "PATCH",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    completed: checkbox.checked
                })
            }
        );

        if (!response.ok) {
            throw new Error(
                "Failed to update response action"
            );
        }

        await openInvestigation(incidentId);
    }
    catch (error) {
        console.error(error);
        alert("Unable to update the response action.");
        await openInvestigation(incidentId);
    }
}


/* =========================================================
   RENDER INCIDENTS
========================================================= */

function renderIncidents(
    incidents
) {

    const container =
        document.getElementById(
            "incidents-container"
        );


    container.innerHTML = "";


    if (incidents.length === 0) {

        container.innerHTML = `
            <div class="loading">

                <p>
                    No matching incidents.
                </p>

            </div>
        `;

        return;
    }


    incidents.forEach(
        incident => {

            const card =
                document.createElement(
                    "div"
                );


            card.className =
                "incident";


            /*
                Database incident structure:

                0  id
                1  incident_type
                2  severity
                3  username
                4  ip_address
                5  failed_attempts
                6  timestamp
                7  status
                8  mitre_technique
                9  analyst_note
                10 risk_score
            */


            const id =
                incident[0];

            const type =
                incident[1];

            const severity =
                incident[2];

            const username =
                incident[3];

            const ip =
                incident[4];

            const failedAttempts =
                incident[5];

            const timestamp =
                incident[6];

            const status =
                incident[7];

            const mitre =
                incident[8];

            const note =
                incident[9] || "";

            const riskScore =
                Number(
                    incident[10] || 0
                );


            const riskLevel =
                getRiskLevel(
                    riskScore
                );


            const badgeClass =
                severity === "CRITICAL"
                    ? "badge-critical"
                    : severity === "HIGH"
                    ? "badge-high"
                    : severity === "MEDIUM"
                    ? "badge-medium"
                    : "badge-low";


            const riskClass =
                riskScore >= 80
                    ? "risk-critical"
                    : riskScore >= 60
                    ? "risk-high"
                    : riskScore >= 30
                    ? "risk-medium"
                    : "risk-low";


            card.innerHTML = `

                <div class="incident-header">

                    <div class="incident-type">

                        🚨 ${escapeHTML(type)}

                        <span class="incident-id">
                            #${id}
                        </span>

                    </div>


                    <span class="badge ${badgeClass}">
                        ${escapeHTML(severity)}
                    </span>

                </div>


                <div class="risk-section">

                    <div class="risk-header">

                        <span>
                            Risk Score
                        </span>

                        <strong class="${riskClass}">
                            ${riskScore}/100
                        </strong>

                    </div>


                    <div class="risk-bar">

                        <div
                            class="risk-fill ${riskClass}"
                            style="width: ${riskScore}%"
                        ></div>

                    </div>


                    <div class="risk-label ${riskClass}">
                        ${riskLevel} RISK
                    </div>

                </div>


                <div class="incident-details">

                    <div class="detail-row">

                        <span>
                            👤 User
                        </span>

                        <strong>
                            ${escapeHTML(username)}
                        </strong>

                    </div>


                    <div class="detail-row">

                        <span>
                            🌐 Source IP
                        </span>

                        <strong>
                            ${escapeHTML(ip)}
                        </strong>

                    </div>


                    <div class="detail-row">

                        <span>
                            🔐 Failed Attempts
                        </span>

                        <strong>
                            ${failedAttempts}
                        </strong>

                    </div>


                    <div class="detail-row">

                        <span>
                            🎯 MITRE ATT&CK
                        </span>

                        <strong>
                            ${escapeHTML(mitre)}
                        </strong>

                    </div>


                    <div class="detail-row">

                        <span>
                            🕒 Timestamp
                        </span>

                        <strong>
                            ${escapeHTML(timestamp)}
                        </strong>

                    </div>

                </div>


                <div class="incident-actions">

                    <button
                        onclick="openInvestigation(${id})"
                    >
                        🔍 Investigate
                    </button>


                    <label>
                        Status
                    </label>


                    <select
                        onchange="
                            updateStatus(
                                ${id},
                                this.value
                            )
                        "
                    >

                        <option
                            value="OPEN"
                            ${
                                status === "OPEN"
                                    ? "selected"
                                    : ""
                            }
                        >
                            OPEN
                        </option>


                        <option
                            value="INVESTIGATING"
                            ${
                                status === "INVESTIGATING"
                                    ? "selected"
                                    : ""
                            }
                        >
                            INVESTIGATING
                        </option>


                        <option
                            value="RESOLVED"
                            ${
                                status === "RESOLVED"
                                    ? "selected"
                                    : ""
                            }
                        >
                            RESOLVED
                        </option>

                    </select>


                    <label>
                        Analyst Note
                    </label>


                    <textarea
                        id="note-${id}"
                        placeholder="Add analyst note..."
                    >${escapeHTML(note)}</textarea>


                    <button
                        onclick="
                            updateNote(${id})
                        "
                    >
                        💾 Save Note
                    </button>

                </div>

            `;


            container.appendChild(
                card
            );
        }
    );
}


/* =========================================================
   FILTER INCIDENTS
========================================================= */

function filterIncidents() {

    const search =
        document.getElementById(
            "search-input"
        ).value.toLowerCase();


    const severity =
        document.getElementById(
            "severity-filter"
        ).value;


    const status =
        document.getElementById(
            "status-filter"
        ).value;


    const filtered =
        allIncidents.filter(
            incident => {

                const matchesSearch =
                    incident
                        .join(" ")
                        .toLowerCase()
                        .includes(search);


                const matchesSeverity =
                    severity === "ALL" ||
                    incident[2] === severity;


                const matchesStatus =
                    status === "ALL" ||
                    incident[7] === status;


                return (
                    matchesSearch &&
                    matchesSeverity &&
                    matchesStatus
                );
            }
        );


    renderIncidents(
        filtered
    );
}


/* =========================================================
   LOAD INCIDENTS
========================================================= */

async function loadIncidents() {

    const response =
        await fetch(
            `${API_URL}/incidents`
        );


    if (!response.ok) {

        throw new Error(
            "Failed to load incidents"
        );
    }


    const data =
        await response.json();


    allIncidents =
        data.incidents;


    filterIncidents();
}


/* =========================================================
   INVESTIGATION
========================================================= */

async function openInvestigation(
    incidentId
) {

    const modal =
        document.getElementById(
            "investigation-modal"
        );


    const content =
        document.getElementById(
            "investigation-content"
        );


    modal.classList.remove(
        "hidden"
    );


    content.innerHTML =
        "Loading investigation...";


    try {

        /*
            Load incident details, response actions,
            and persisted audit history simultaneously.
        */

        const [
            incidentResponse,
            historyResponse,
            responseActionsResponse
        ] = await Promise.all([

            fetch(
                `${API_URL}/incidents/${incidentId}`
            ),

            fetch(
                `${API_URL}/incidents/${incidentId}/history`
            ),

            fetch(
                `${API_URL}/incidents/${incidentId}/response-actions`
            )
        ]);


        if (!incidentResponse.ok) {

            throw new Error(
                "Incident not found"
            );
        }


        if (!historyResponse.ok) {

            throw new Error(
                "Unable to load incident history"
            );
        }


        if (!responseActionsResponse.ok) {

            throw new Error(
                "Unable to load response actions"
            );
        }


        const incident =
            await incidentResponse.json();


        const historyData =
            await historyResponse.json();


        const responseActionsData =
            await responseActionsResponse.json();


        const history =
            historyData.history || [];


        const responseActions =
            responseActionsData.actions || [];


        const riskScore =
            Number(
                incident.risk_score || 0
            );


        const riskLevel =
            getRiskLevel(
                riskScore
            );


        const riskClass =
            riskScore >= 80
                ? "risk-critical"
                : riskScore >= 60
                ? "risk-high"
                : riskScore >= 30
                ? "risk-medium"
                : "risk-low";


        const timelineHTML =
            renderIncidentHistory(
                history
            );


        const responseActionsHTML =
            renderResponseActions(
                responseActions,
                incidentId
            );


        content.innerHTML = `

            <div class="investigation-grid">


                <div>

                    <span>
                        Incident ID
                    </span>

                    <strong>
                        #${incident.id}
                    </strong>

                </div>


                <div>

                    <span>
                        Type
                    </span>

                    <strong>
                        ${escapeHTML(incident.type)}
                    </strong>

                </div>


                <div>

                    <span>
                        Severity
                    </span>

                    <strong>
                        ${escapeHTML(incident.severity)}
                    </strong>

                </div>


                <div>

                    <span>
                        Status
                    </span>

                    <strong>
                        ${escapeHTML(incident.status)}
                    </strong>

                </div>


                <div>

                    <span>
                        Username
                    </span>

                    <strong>
                        ${escapeHTML(incident.username)}
                    </strong>

                </div>


                <div>

                    <span>
                        Source IP
                    </span>

                    <strong>
                        ${escapeHTML(incident.ip_address)}
                    </strong>

                </div>


                <div>

                    <span>
                        Failed Attempts
                    </span>

                    <strong>
                        ${incident.failed_attempts}
                    </strong>

                </div>


                <div>

                    <span>
                        MITRE ATT&CK
                    </span>

                    <strong>
                        ${escapeHTML(
                            incident.mitre_technique
                        )}
                    </strong>

                </div>


                <div>

                    <span>
                        Risk Score
                    </span>

                    <strong class="${riskClass}">
                        ${riskScore}/100
                    </strong>

                </div>


                <div>

                    <span>
                        Risk Level
                    </span>

                    <strong class="${riskClass}">
                        ${riskLevel}
                    </strong>

                </div>

            </div>


            <div class="investigation-risk">

                <div class="risk-header">

                    <span>
                        Overall Risk
                    </span>

                    <strong class="${riskClass}">
                        ${riskScore}/100
                    </strong>

                </div>


                <div class="risk-bar">

                    <div
                        class="risk-fill ${riskClass}"
                        style="width: ${riskScore}%"
                    ></div>

                </div>

            </div>


            <div class="investigation-note">

                <h3>
                    📝 Analyst Note
                </h3>

                <p>
                    ${
                        escapeHTML(
                            incident.analyst_note
                        ) ||
                        "No analyst note recorded."
                    }
                </p>

            </div>


            <div class="investigation-response-actions">

                <div class="response-actions-header">
                    <div>
                        <h3>🛡️ Response Actions</h3>
                        <p>
                            Simulated SOC response actions —
                            no real system changes are performed.
                        </p>
                    </div>

                    <span>Manual case tracking</span>
                </div>

                <div class="response-actions-grid">
                    ${responseActionsHTML}
                </div>

            </div>


            <div class="investigation-timeline">

                <h3>
                    🕒 Investigation Timeline
                </h3>

                ${timelineHTML}

            </div>

        `;

    }

    catch (error) {

        console.error(
            error
        );


        content.innerHTML = `

            <p class="error">
                Unable to load investigation.
            </p>

        `;
    }
}


/* =========================================================
   CLOSE INVESTIGATION
========================================================= */

function closeInvestigation() {

    document
        .getElementById(
            "investigation-modal"
        )
        .classList.add(
            "hidden"
        );
}


document.addEventListener("keydown", event => {
    if (event.key === "Escape") {
        closeInvestigation();
    }
});


/* =========================================================
   LOAD EVERYTHING
========================================================= */

async function loadDashboard() {

    try {

        await Promise.all([
            loadStats(),
            loadIncidents()
        ]);

    }

    catch (error) {

        console.error(
            error
        );


        document.getElementById(
            "incidents-container"
        ).innerHTML = `

            <p class="error">
                Unable to connect to SOC API.
            </p>

        `;
    }
}


/* =========================================================
   INITIAL LOAD
========================================================= */

loadDashboard();


/*
    Refresh dashboard every 5 seconds.
*/

setInterval(
    loadDashboard,
    5000
);
