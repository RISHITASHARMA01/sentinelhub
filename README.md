# SentinelHub — A Self-Built SOC Platform

SentinelHub ingests security-relevant logs (SSH auth logs, web server logs),
normalizes them into a common schema, runs detection rules mapped to MITRE
ATT&CK, enriches findings with threat intelligence, and surfaces everything
in a live dashboard — a small, from-scratch version of what a SOC's SIEM
tooling actually does.

Built in phases, each one runnable and testable on its own — see
[Project status](#project-status).

[![CI](https://github.com/RISHITASHARMA01/sentinelhub/actions/workflows/ci.yml/badge.svg)](https://github.com/RISHITASHARMA01/sentinelhub/actions/workflows/ci.yml)
<!-- update the username/repo above if you push this under a different GitHub org/repo name -->

## Screenshots

| Overview | Alerts (expanded) | Logs |
|---|---|---|
| ![Overview](docs/screenshots/overview.png) | ![Alerts expanded](docs/screenshots/alerts-expanded.png) | ![Logs](docs/screenshots/logs.png) |

## Architecture

```
Raw logs (SSH, nginx, honeypot)
        │
        ▼
  Log Parser (app/services/log_parser.py)
   - regex-based normalization per source type
        │
        ▼
  Ingestion API (app/api/ingestion.py)
   - POST /ingest/line   (single line, for streaming agents)
   - POST /ingest/file   (bulk upload, for testing/backfill)
        │
        ▼
  PostgreSQL (LogEvent table)
        │
        ├────────────────────────────┐
        ▼                            ▼
  Query API (app/api/logs.py)   Detection Engine (app/services/detection_engine.py)
   - GET /logs/                  - rule-based analysis of unprocessed LogEvents
   - GET /logs/stats/summary     - sliding-window burst detection per src_ip
                                  - maps findings to MITRE ATT&CK technique IDs
                                       │
                                       ▼
                                 PostgreSQL (Alert table)
                                       │
                                       ▼
                                 Detection + Alerts API
                                  - POST /detect/run          (manual trigger)
                                  - GET  /alerts/              (filter + paginate)
                                  - GET  /alerts/{id}
```

### Detection rules (Phase 2)

| Rule | MITRE Technique | Trigger |
|---|---|---|
| `brute_force_login` | T1110 (Brute Force) | 5+ failed logins from one IP within 60s |
| `credential_stuffing` | T1110 (Brute Force) | Same as above, but the burst spans 5+ distinct usernames — flagged `high` severity instead of `medium` |
| `web_path_scanning` | T1595 (Active Scanning) | 8+ requests to known attack paths (`/wp-login.php`, `/.env`, `/admin`, ...) or 404s from one IP within 60s |
| `off_hours_login` | T1078 (Valid Accounts) | A *successful* login between 00:00–05:00 — low severity/informational |

Thresholds and windows live as constants at the top of `detection_engine.py`
so they're easy to tune (and easy to point to in an interview).

### Threat intel enrichment (Phase 3)

When the detection engine creates an alert, it automatically looks up the
attacking `src_ip` against **AbuseIPDB**'s free-tier reputation API
(`backend/app/services/threat_intel.py`) and stores the result — abuse
confidence score, country, ISP, total report count — in `Alert.enrichment`.

```
Detection Engine creates an Alert
        │
        ▼
  threat_intel.get_ip_reputation(src_ip)
   - in-memory cache check (1hr TTL) ──► cache hit? return cached data
        │ cache miss
        ▼
  AbuseIPDB API  ──(no key / network error)──► log warning, return None
        │ success
        ▼
  Alert.enrichment (JSONB)
```

Design notes:
- **No API key configured?** Enrichment is skipped with a logged warning —
  detection and alerting keep working normally either way. Threat intel is
  additive, not a dependency.
- **Caching**: a simple in-memory `{ip: (timestamp, data)}` dict with a
  1-hour TTL, so a repeat-offender IP that trips several alerts doesn't
  burn through the free tier's daily quota re-checking itself each time.
- **Manual re-enrichment**: `POST /alerts/{id}/enrich` re-runs the lookup
  for one alert — useful for alerts created before a key was configured, or
  to force a fresher check past the cache TTL.

#### Getting a free AbuseIPDB API key
1. Register at https://www.abuseipdb.com/register (free tier is enough).
2. Grab your API key from https://www.abuseipdb.com/account/api.
3. Copy `.env.example` to `.env` (same folder as `docker-compose.yml`) and
   set `ABUSEIPDB_API_KEY=<your key>`.
4. Restart the backend: `docker compose up -d` (compose reads `.env`
   automatically for variable substitution).

```bash
cp .env.example .env
# edit .env, then:
docker compose up -d
curl -X POST http://localhost:8001/detect/run
curl "http://localhost:8001/alerts/" | python3 -m json.tool   # enrichment should now be populated
```

### Dashboard (Phase 4)

A React + Vite + Tailwind dashboard in `frontend/`, styled as a dark
SOC console (Splunk/Grafana-style) rather than a generic admin template:

- **Overview** (`/`) — total events / open alerts / unique attacker IP
  stat cards, a combined events-vs-alerts time-series chart, and an
  alerts-by-severity breakdown, all via Recharts.
- **Alerts** (`/alerts`) — sortable, server-filterable (severity / status /
  source IP) table. Clicking a row expands it in place to show the
  triggering log event, MITRE ATT&CK info, and threat intel enrichment.
  The status dropdown drives the new `PATCH /alerts/{id}` endpoint.
- **Logs** (`/logs`) — searchable (free-text over the raw log line),
  filterable, paginated table of raw `LogEvent` rows.

Data fetching is centralized in `frontend/src/api/client.js`, base URL
configurable via `VITE_API_URL`. Two new backend endpoints power it:
`GET /alerts/stats/summary` / `GET /alerts/stats/timeseries` /
`GET /logs/stats/timeseries` for the charts, and `PATCH /alerts/{id}` for
status changes (open → investigating → resolved / false_positive).

#### Running the dashboard

```bash
docker compose up -d          # frontend now included, served on :3001
open http://localhost:3001
```

Or for local dev with hot reload (outside Docker):
```bash
cd frontend
npm install
cp .env.example .env          # VITE_API_URL defaults to localhost:8001
npm run dev                   # http://localhost:5173
```

Both `http://localhost:3001` (Docker) and `http://localhost:5173` (Vite
dev server) are already allowed in the backend's CORS config
(`backend/app/main.py`).

Phase 5 (honeypot integration) was an optional stretch goal and was
skipped for this project — see [Project status](#project-status).

### CI/CD & deployment (Phase 6)

`.github/workflows/ci.yml` runs on every push/PR: backend tests against a
real Postgres service container, a production Docker build check for the
backend (proving the shipped image builds cleanly with no dev/test
dependencies in it), and a frontend build check.

Deployment guide (Render, free tier): see **[DEPLOYMENT.md](DEPLOYMENT.md)**.

#### Production hygiene in the Dockerfiles

- **No dev/test dependencies in the shipped image.** `backend/requirements-dev.txt`
  (just `pytest`) is only installed when `docker compose` passes
  `INSTALL_DEV=true` — real deploys and CI's build-check build without it.
- **Non-root containers.** The backend runs as a created `appuser` (UID
  1000); the frontend uses `nginxinc/nginx-unprivileged` instead of plain
  `nginx` so its worker process never runs as root either.
- **Slim/multi-stage base images.** `python:3.11-slim` for the backend;
  the frontend is a multi-stage build (Node to compile, nginx-unprivileged
  alpine to serve) so Node/npm never ship in the final image.
- **Runtime-configurable port.** The backend's `CMD` reads `$PORT` (with
  an 8000 fallback for local Docker Compose) since PaaS providers like
  Render assign it dynamically rather than letting you hardcode 8000.

## Why this design

- **Normalization first**: every log source is different, but the detection
  engine should only ever have to think about one schema (`LogEvent`).
  This is the same pattern real SIEM tools (Splunk, Elastic) use internally.
- **Two ingestion paths**: a line-based endpoint for a live tailing agent,
  and a file-upload endpoint so you can bulk-test with sample data (like
  `docs/sample_auth.log`) without needing a live server generating logs.
- **Environment-based config**: DB credentials come from `DATABASE_URL`,
  never hardcoded — a basic but important security hygiene habit.

## How to demo this in an interview

Three talking points that go beyond "it works," in case you get asked
to go deeper on a design decision:

1. **Why normalize before detecting anything.** SSH logs, web server
   logs, and (eventually) honeypot JSON all look completely different on
   the wire. `log_parser.py` converts every source into one `LogEvent`
   shape up front, so `detection_engine.py` never has to know or care
   where an event came from — it just asks "did too many `auth_failure`
   events happen from one IP in 60 seconds?" Add a new log source later
   and zero detection code changes; you only write a new parser function.
2. **Why map findings to MITRE ATT&CK instead of inventing my own labels.**
   MITRE ATT&CK is the industry's shared vocabulary for attack behavior —
   a real SOC alert that says "T1110" means the same thing everywhere,
   the same way an HTTP 404 means the same thing everywhere. Using it
   here is a small thing that signals I know how real security teams
   communicate findings, not just how to write a regex.
3. **Rule-based detection vs. ML — and why I started with rules.**
   Every alert here traces back to one explicit, human-readable condition
   (`BRUTE_FORCE_THRESHOLD = 5` failed logins in `60` seconds) — you can
   point at the exact line that fired and explain it to a non-technical
   stakeholder in one sentence. An ML anomaly detector could catch attack
   patterns nobody's explicitly coded for, but it trades that explainability
   away and needs labeled training data and tuning to avoid drowning
   analysts in false positives. Real SOCs generally start with rules
   (Sigma rules, Splunk correlation searches) for exactly this reason,
   and layer ML on top later for the patterns rules can't catch.

## Running locally

### Option A: Docker Compose (recommended)
```bash
docker compose up --build
```
- API: http://localhost:8001, interactive docs at http://localhost:8001/docs
  (mapped from the container's internal port 8000 — see `docker-compose.yml`)
- Dashboard: http://localhost:3001

### Option B: Manual
```bash
cd backend
pip install -r requirements.txt
# start your own Postgres, then:
export DATABASE_URL=postgresql://sentinel:sentinel@localhost:5432/sentinelhub
uvicorn app.main:app --reload
```

## Testing ingestion with sample data

```bash
curl -X POST http://localhost:8001/ingest/file \
  -F "file=@docs/sample_auth.log" \
  -F "source_hint=system"
```

Then check it landed:
```bash
curl http://localhost:8001/logs/stats/summary
curl "http://localhost:8001/logs/?event_type=auth_failure"
```

The sample log contains a simulated brute-force burst (10 failed SSH logins
from `203.0.113.5` within ~20 seconds, across 8 different usernames).

## Testing detection (Phase 2)

```bash
# 1. ingest the sample log (if you haven't already)
curl -X POST http://localhost:8001/ingest/file \
  -F "file=@docs/sample_auth.log" \
  -F "source_hint=system"

# 2. run the detection engine
curl -X POST http://localhost:8001/detect/run
# -> {"new_alerts": 1}

# 3. see what fired
curl "http://localhost:8001/alerts/?src_ip=203.0.113.5"
```

Because the sample burst spans 8 distinct usernames (admin, root, test,
oracle, postgres, ubuntu, pi, git), it's correctly classified as
`credential_stuffing` (high severity) rather than plain `brute_force_login` —
spraying many accounts is a different, more automated pattern than
repeatedly guessing one account's password. Both map to MITRE **T1110**.

Re-running `POST /detect/run` on the same data returns `{"new_alerts": 0}` —
each `LogEvent` is marked `processed_for_detection` once scanned, so nothing
gets double-alerted.

### Running the automated tests

```bash
docker compose exec backend pytest -v
```

`backend/app/tests/test_detection.py` ingests the sample log through the
real API, runs detection, and asserts the `T1110` alert for `203.0.113.5` is
created — and that a second run doesn't duplicate it.

### Schema note

Phase 2 added a `processed_for_detection` column to `LogEvent`. Since this
project doesn't have Alembic migrations yet (a known "next step" — see
below), if you're upgrading a Postgres volume from Phase 1 you'll need to
either drop the affected tables (fine if they're empty/test data) or run:
```sql
ALTER TABLE log_events ADD COLUMN processed_for_detection BOOLEAN NOT NULL DEFAULT false;
```

## Project status
- [x] Phase 1: Ingestion pipeline + normalized log storage
- [x] Phase 2: Detection engine + MITRE ATT&CK mapping
- [x] Phase 3: Threat intelligence enrichment
- [x] Phase 4: Dashboard
- [ ] Phase 5: Honeypot integration — skipped (optional stretch goal)
- [x] Phase 6: CI/CD + deployment guide + production hygiene

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for deploying to Render.
