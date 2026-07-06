"""
Phase 2 integration test.

Runs against the real Postgres from docker-compose (DATABASE_URL is already
set for the backend container) rather than mocks -- for a detection engine,
the interesting bugs live in the SQL queries and time-window logic, and
mocking the DB would hide exactly those bugs. This mirrors the manual test
flow documented in the README: ingest the sample log, run detection, check
the alerts.

Run it with:
    docker compose exec backend pytest -v
"""

from fastapi.testclient import TestClient

from app.main import app
from app.core.database import SessionLocal, Base, engine
from app.models.models import Alert, LogEvent

# Normally main.py's startup handler creates these tables the moment the
# app boots -- true for the real backend container, which has always been
# running for a while by the time you run tests against it. A fresh CI
# Postgres has never seen that startup event fire, so _reset_tables()'s
# raw DELETE below would hit tables that don't exist yet. Create them
# directly rather than relying on app startup having already happened.
Base.metadata.create_all(bind=engine)

client = TestClient(app)


def _reset_tables():
    """Wipe log_events/alerts so the test is repeatable across runs."""
    db = SessionLocal()
    try:
        db.query(Alert).delete()
        db.query(LogEvent).delete()
        db.commit()
    finally:
        db.close()


def test_brute_force_alert_created_from_sample_log():
    _reset_tables()

    with open("docs/sample_auth.log") as f:
        log_bytes = f.read().encode("utf-8")

    ingest_resp = client.post(
        "/ingest/file",
        files={"file": ("sample_auth.log", log_bytes, "text/plain")},
        data={"source_hint": "system"},
    )
    assert ingest_resp.status_code == 200
    assert ingest_resp.json()["parsed"] > 0

    detect_resp = client.post("/detect/run")
    assert detect_resp.status_code == 200
    assert detect_resp.json()["new_alerts"] >= 1

    alerts_resp = client.get("/alerts/", params={"src_ip": "203.0.113.5"})
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()

    assert len(alerts) == 1, f"expected exactly one alert for 203.0.113.5, got {alerts}"
    alert = alerts[0]
    assert alert["mitre_technique_id"] == "T1110"
    # The sample burst spans 8 distinct usernames (admin, root, test, oracle,
    # postgres, ubuntu, pi, git), so it correctly classifies as credential
    # stuffing rather than plain single-account brute force.
    assert alert["rule_name"] == "credential_stuffing"
    assert alert["severity"] == "high"


def test_detect_run_is_idempotent_on_already_processed_events():
    _reset_tables()

    with open("docs/sample_auth.log") as f:
        log_bytes = f.read().encode("utf-8")

    client.post(
        "/ingest/file",
        files={"file": ("sample_auth.log", log_bytes, "text/plain")},
        data={"source_hint": "system"},
    )
    first_run = client.post("/detect/run").json()["new_alerts"]
    second_run = client.post("/detect/run").json()["new_alerts"]

    assert first_run >= 1
    assert second_run == 0, "re-running detection on the same events should not create duplicate alerts"
