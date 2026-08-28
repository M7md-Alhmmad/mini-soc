# Testing Mini SOC

This guide is for checking the complete local workflow before publishing a release. It uses a temporary SQLite database so the normal development database is left alone.

## 1. Prepare PowerShell

Stop any Mini SOC monitor or API process with `Ctrl+C`, then open a fresh PowerShell window in the repository root:

```powershell
.venv\Scripts\Activate.ps1
$env:MINI_SOC_DATABASE = Join-Path $env:TEMP "mini-soc-release-test.db"
```

For a completely fresh run, remove only that temporary database:

```powershell
Remove-Item -LiteralPath $env:MINI_SOC_DATABASE, "${env:MINI_SOC_DATABASE}-wal", "${env:MINI_SOC_DATABASE}-shm" -Force -ErrorAction SilentlyContinue
```

## 2. Run the automated tests

```powershell
python -m pytest -q
```

The expected result is `19 passed`. The known Starlette/httpx deprecation warning does not fail the tests.

## 3. Start the monitor

In Terminal 1:

```powershell
.venv\Scripts\Activate.ps1
$env:MINI_SOC_DATABASE = Join-Path $env:TEMP "mini-soc-release-test.db"
python -m src monitor
```

On a new database, the monitor should start at event 0 and wait for new events. Leave this terminal running.

## 4. Start the dashboard

In Terminal 2:

```powershell
.venv\Scripts\Activate.ps1
$env:MINI_SOC_DATABASE = Join-Path $env:TEMP "mini-soc-release-test.db"
python -m src serve
```

Open <http://127.0.0.1:8000/dashboard>. The interactive API documentation is at <http://127.0.0.1:8000/docs>.

## 5. Generate test activity

In Terminal 3:

```powershell
.venv\Scripts\Activate.ps1
$env:MINI_SOC_DATABASE = Join-Path $env:TEMP "mini-soc-release-test.db"
python -m src simulate brute-force --username demo-user --ip 203.0.113.10 --count 8
python -m src simulate port-scan --username scanner --ip 198.51.100.25 --count 15
python -m src simulate account-compromise --username demo-admin --ip 203.0.113.50 --count 5
```

Terminal 1 should report `BRUTE_FORCE`, `PORT_SCAN`, and `ACCOUNT_COMPROMISE`, followed by an updated event checkpoint. Repeating the same scenario may produce `DEDUP`, which means an existing recent incident was reused.

## 6. Check the dashboard workflow

Confirm that the dashboard shows incident statistics, severities, risk scores, MITRE mappings, search, and filters. Then test one incident:

1. Open **Investigate** and review the details.
2. Change the card status to `INVESTIGATING`.
3. Add and save an analyst note.
4. Reopen **Investigate** and complete two response actions.
5. Refresh the page and confirm the changes are still present.
6. Check that the investigation timeline records the updates.
7. Change the incident to `RESOLVED` and confirm the statistics update.

## 7. Check offline checkpoint recovery

Note the last `Checkpoint updated: event #N` message in Terminal 1, then stop the monitor with `Ctrl+C`.

Generate an event batch while it is stopped:

```powershell
python -m src simulate brute-force --username offline-user --ip 198.51.100.77 --count 5
```

Restart the monitor:

```powershell
python -m src monitor
```

It should start from the saved checkpoint, process the offline events, create or deduplicate the incident, and advance the checkpoint. Stop and restart it once more. The same batch should not be processed again.

## 8. Run the stale port-scan regression

```powershell
python -m pytest -q -vv tests/test_detection.py::test_port_scan_survives_trailing_stale_event
```

`1 passed` confirms that a valid ten-event scan is still detected when a later stale event appears outside the five-minute window.

## 9. Check the API

Use <http://127.0.0.1:8000/docs> to try:

- `GET /incidents`
- `GET /incidents/{incident_id}/history`
- `GET /incidents/{incident_id}/response-actions`
- `PATCH /incidents/{incident_id}/status`
- `PATCH /incidents/{incident_id}/note`
- `PATCH /incidents/{incident_id}/response-actions/{action_type}`
- `GET /stats`

Valid requests should return HTTP 200 responses and remain visible after a page refresh.

## 10. Finish the check

Stop the monitor and API with `Ctrl+C`, then run:

```powershell
git status
```

Temporary databases, logs, caches, and virtual environments should remain ignored. Only intentional source or documentation changes should appear.
