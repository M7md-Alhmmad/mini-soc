# Mini SOC

Mini SOC is a self-contained Security Operations Center learning project. It stores synthetic security events in SQLite, detects suspicious patterns, correlates alerts into incidents, and provides a browser dashboard for investigation, status changes, notes, risk scores, and audit history.

## Features

- Brute-force detection: 5 or more failed logins in 5 minutes
- Port-scan detection: 10 or more scan events in a rolling 5-minute window
- Account-compromise correlation: repeated failures followed by a successful login
- Five-minute rolling context for incremental monitoring
- Time-bounded incident deduplication
- MITRE ATT&CK mapping and risk scoring
- FastAPI API with interactive documentation
- Responsive dashboard with filtering and investigation history
- Simulated incident containment and remediation tracking
- SQLite persistence with indexes and audit history

The simulators only insert synthetic records into the local database. They do not send network traffic.

## Detection Rules and MITRE ATT&CK

| Detection | MITRE ATT&CK | Purpose |
| --- | --- | --- |
| Brute Force | T1110 | Repeated authentication failures |
| Port Scan | T1046 | Network service scanning activity |
| Suspicious Login / Account Compromise | T1078 | Successful use of an account after suspicious authentication activity |

## Quick start

Python 3.10 or newer is required.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m src serve
```

Open <http://127.0.0.1:8000/dashboard>. API documentation is at <http://127.0.0.1:8000/docs>.

The existing `data/security_events.db` is used by default. To use another database, set `MINI_SOC_DATABASE` before starting a command.

```powershell
$env:MINI_SOC_DATABASE = "C:\temp\mini-soc.db"
python -m src serve
```

## Quick Demo

1. In PowerShell, create the environment and install the project:

   ```powershell
   cd C:\path\to\mini-soc
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   python -m pip install -e ".[dev]"
   ```

2. In Terminal 1, activate the environment and start the live monitor:

   ```powershell
   .venv\Scripts\Activate.ps1
   python -m src monitor
   ```

3. In Terminal 2, activate the environment and start FastAPI and the dashboard:

   ```powershell
   .venv\Scripts\Activate.ps1
   python -m src serve
   ```

4. In Terminal 3, activate the environment and run the supported attack simulations:

   ```powershell
   .venv\Scripts\Activate.ps1
   python -m src simulate brute-force --username demo-user --ip 203.0.113.10 --count 8
   python -m src simulate port-scan --username scanner --ip 198.51.100.25 --count 15
   python -m src simulate account-compromise --username demo-admin --ip 203.0.113.50 --count 5
   ```

5. Open <http://127.0.0.1:8000/dashboard>. Select **Investigate** on an incident, change its status, add an analyst note, and complete appropriate simulated response actions. Refresh and reopen the incident to confirm that the values and investigation timeline persisted.

## Commands

```powershell
# Insert a synthetic scenario, then scan it
python -m src simulate account-compromise
python -m src detect

# Watch for new events inserted by another terminal
python -m src monitor

# Generate 50 ordinary sample events
python -m src generate --count 50

# Other safe local scenarios
python -m src simulate brute-force --username alice --ip 203.0.113.10 --count 8
python -m src simulate port-scan --ip 198.51.100.25 --count 15
```

Run `python -m src --help` for all options.

## Reliable live monitoring

The monitor stores its last successfully processed event ID in SQLite. Events created while it is offline are processed after restart, and a failed detection cycle leaves the checkpoint unchanged so the batch can be retried. On first use, the checkpoint starts at the database's current latest event to avoid unexpectedly rescanning old demo data.

## Incident Response Actions

The investigation view supports a manual SOC lifecycle:

**Detect → Investigate → Contain / Remediate → Resolve**

Analysts can track whether they have completed these response activities for an incident:

- Disable account
- Reset password
- Block attacker IP
- Revoke active sessions
- Isolate endpoint
- Collect evidence

Each change is persisted in SQLite and added to the incident history. Actions can also be reopened if they were marked complete accidentally. They do not automatically change the incident status, and analysts should select only the actions appropriate to the incident.

These actions are simulated case-management controls for demonstration purposes and do not execute real changes on the host, identity provider, firewall, or endpoints.

## Known Limitations

Mini SOC is a focused local portfolio demonstration rather than a production SIEM or SOAR platform. Its detection rules intentionally operate on simplified synthetic telemetry: brute-force activity is grouped using the available username and IP data, port scans use simulated scan events rather than packet capture or destination-port telemetry, and account-compromise correlation requires the relevant simulated authentication sequence. The live monitor is designed for one monitoring process. Dashboard and API authentication and authorization are outside the current local-demo scope. Response actions provide persistent case-management tracking only; they do not modify real accounts, firewalls, endpoints, passwords, or sessions.

## Development

```powershell
pytest
```

Important API routes include `/events`, `/incidents`, `/incidents/{id}`, `/incidents/{id}/history`, `/incidents/{id}/response-actions`, `/stats`, and the incident status/note/response-action patch routes. SQLite writes are parameterized, analyst content is escaped before dashboard rendering, and controlled status and response-action values are validated.

## Project layout

```text
frontend/    Dashboard HTML, CSS, and JavaScript
src/         API, storage, detection, monitoring, and simulators
data/        SQLite database
logs/        Generated text event log
tests/       Automated backend and detection tests
```
