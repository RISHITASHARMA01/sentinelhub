# SentinelHub Simulation Lab

The simulation engine generates fictional Windows Security
and Sysmon events for defensive detection testing.

No real attacks or remote connections are performed.

## Run Simulation

curl -X POST http://localhost:8001/simulation/run

## Trigger Detection

curl -X POST http://localhost:8001/detect/run

## Expected Coverage

- Privilege escalation indicators
- Administrative group modification
- Scheduled task persistence
- Service installation
- Registry modification
- Audit log clearing
- DNS anomalies
- Periodic network activity
- Multi-category event correlation

Synthetic events are labelled in parsed_fields.

The simulation endpoint is intended for local development.
Repeated simulation runs generate new records and alerts.
