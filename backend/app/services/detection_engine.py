"""
Detection Engine
----------------
Turns normalized LogEvent rows into Alert rows using simple, explainable
rule-based logic -- no ML here on purpose. Rule-based detection is what most
real SOCs start with (Splunk correlation searches, Sigma rules, etc.) because
every alert can be explained by pointing at the exact condition that fired.
The trade-off worth naming in an interview: it only catches patterns you've
explicitly encoded, unlike anomaly-detection approaches that can surface
novel behavior at the cost of more false positives and less explainability.

Each rule is mapped to a MITRE ATT&CK technique ID so alerts read like real
SOC output instead of ad-hoc "something looks wrong" messages.
"""

from app.services.kerberos_detection import detect_kerberos
from datetime import timedelta
from collections import defaultdict
from typing import List

from sqlalchemy.orm import Session

from app.models.models import LogEvent, Alert, Severity
from app.services.threat_intel import get_ip_reputation

# --- Tunable thresholds ---------------------------------------------------
# Kept as module-level constants (rather than hardcoded inline) so they're
# easy to point to in an interview: "here's how I'd tune this for a noisier
# or quieter environment."

BRUTE_FORCE_THRESHOLD = 5            # failed logins...
BRUTE_FORCE_WINDOW_SECONDS = 60      # ...within this many seconds
CREDENTIAL_STUFFING_DISTINCT_USERS = 5  # distinct usernames in a burst -> stuffing, not plain brute force

WEB_SCAN_THRESHOLD = 8               # suspicious requests...
WEB_SCAN_WINDOW_SECONDS = 60         # ...within this many seconds
SUSPICIOUS_PATHS = {
    "/wp-login.php", "/wp-admin", "/.env", "/admin", "/administrator",
    "/phpmyadmin", "/.git/config", "/config.php", "/xmlrpc.php",
}

OFF_HOURS_START_HOUR = 0   # midnight
OFF_HOURS_END_HOUR = 5     # 5am (exclusive) -- login *successes* in this window are flagged


def _is_suspicious_web_request(event: LogEvent) -> bool:
    fields = event.parsed_fields or {}
    if fields.get("status") == 404:
        return True
    path = fields.get("path", "")
    return any(path.startswith(p) for p in SUSPICIOUS_PATHS)


def _find_bursts(events: List[LogEvent], window_seconds: int, threshold: int) -> List[List[LogEvent]]:
    """
    Sliding-window burst finder. `events` must already be sorted by
    timestamp and belong to a single src_ip. Returns a list of bursts,
    each a list of >= threshold events that all fall within window_seconds
    of the first event in that burst.

    Once a burst is emitted we jump the pointer past it entirely instead of
    sliding one event at a time -- that's what keeps a single 10-login
    attack from producing several overlapping alerts instead of one.
    """
    bursts = []
    n = len(events)
    i = 0
    while i < n:
        j = i
        while j + 1 < n and (events[j + 1].timestamp - events[i].timestamp).total_seconds() <= window_seconds:
            j += 1
        if (j - i + 1) >= threshold:
            bursts.append(events[i:j + 1])
            i = j + 1
        else:
            i += 1
    return bursts


def _alert_already_exists(db: Session, rule_name: str, src_ip: str, burst_start) -> bool:
    """
    Dedup guard: skip creating a new alert if one for this rule/IP already
    exists from around the same incident. Combined with
    `processed_for_detection` (which stops us re-scanning the same events
    at all across runs), this keeps one attack burst from generating a pile
    of duplicate alerts.
    """
    since = burst_start - timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS)
    return (
        db.query(Alert)
        .filter(Alert.rule_name == rule_name, Alert.src_ip == src_ip, Alert.created_at >= since)
        .first()
        is not None
    )


def detect_brute_force(db: Session, events: List[LogEvent]) -> int:
    """
    T1110 - Brute Force: N+ failed logins from the same IP in a short
    window. If that burst also spans many distinct usernames, we re-tag it
    as credential stuffing / distributed brute force with higher severity --
    spraying many accounts is a meaningfully different (and typically more
    automated) pattern than repeatedly guessing one account's password.
    """
    by_ip = defaultdict(list)
    for e in events:
        if e.event_type == "auth_failure" and e.src_ip:
            by_ip[e.src_ip].append(e)

    created = 0
    for src_ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)
        for burst in _find_bursts(ip_events, BRUTE_FORCE_WINDOW_SECONDS, BRUTE_FORCE_THRESHOLD):
            distinct_users = sorted({e.username for e in burst if e.username})
            burst_start, burst_end = burst[0].timestamp, burst[-1].timestamp

            if len(distinct_users) >= CREDENTIAL_STUFFING_DISTINCT_USERS:
                rule_name = "credential_stuffing"
                severity = Severity.high
                description = (
                    f"{len(burst)} failed logins from {src_ip} across "
                    f"{len(distinct_users)} distinct usernames between "
                    f"{burst_start} and {burst_end} -- consistent with "
                    f"credential stuffing / distributed password spraying."
                )
            else:
                rule_name = "brute_force_login"
                severity = Severity.high if len(burst) >= BRUTE_FORCE_THRESHOLD * 2 else Severity.medium
                description = (
                    f"{len(burst)} failed logins from {src_ip} between "
                    f"{burst_start} and {burst_end} "
                    f"(usernames tried: {', '.join(distinct_users) or 'unknown'})."
                )

            if _alert_already_exists(db, rule_name, src_ip, burst_start):
                continue

            db.add(Alert(
                triggering_event_id=burst[-1].id,
                rule_name=rule_name,
                mitre_technique_id="T1110",
                mitre_technique_name="Brute Force",
                severity=severity,
                description=description,
                src_ip=src_ip,
                enrichment=get_ip_reputation(src_ip),
            ))
            created += 1

    return created


def detect_web_scanning(db: Session, events: List[LogEvent]) -> int:
    """
    T1595 - Active Scanning: a burst of 404s or requests to known
    attack-surface paths (wp-login.php, .env, /admin, ...) from one IP --
    the signature of an automated scanner probing for exposed endpoints.
    """
    by_ip = defaultdict(list)
    for e in events:
        if e.event_type == "http_request" and e.src_ip and _is_suspicious_web_request(e):
            by_ip[e.src_ip].append(e)

    created = 0
    for src_ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e.timestamp)
        for burst in _find_bursts(ip_events, WEB_SCAN_WINDOW_SECONDS, WEB_SCAN_THRESHOLD):
            burst_start, burst_end = burst[0].timestamp, burst[-1].timestamp
            paths = sorted({(e.parsed_fields or {}).get("path", "?") for e in burst})

            if _alert_already_exists(db, "web_path_scanning", src_ip, burst_start):
                continue

            db.add(Alert(
                triggering_event_id=burst[-1].id,
                rule_name="web_path_scanning",
                mitre_technique_id="T1595",
                mitre_technique_name="Active Scanning",
                severity=Severity.medium,
                description=(
                    f"{len(burst)} suspicious web requests (404s / known attack "
                    f"paths) from {src_ip} between {burst_start} and {burst_end}. "
                    f"Paths probed: {', '.join(paths[:10])}{'...' if len(paths) > 10 else ''}"
                ),
                src_ip=src_ip,
                enrichment=get_ip_reputation(src_ip),
            ))
            created += 1

    return created


def detect_off_hours_login(db: Session, events: List[LogEvent]) -> int:
    """
    T1078 - Valid Accounts: a *successful* login during an unusual hour
    (00:00-05:00 by default). Low severity/informational on its own -- a
    real analyst would correlate it with other signals -- but worth
    surfacing since stolen credentials are often used off-hours specifically
    to avoid a live admin noticing.
    """
    created = 0
    for e in events:
        if e.event_type != "auth_success" or not e.src_ip:
            continue
        if not (OFF_HOURS_START_HOUR <= e.timestamp.hour < OFF_HOURS_END_HOUR):
            continue

        # One event = one incident here, so the processed_for_detection
        # flag (this exact event is never re-scanned) is dedup enough.
        db.add(Alert(
            triggering_event_id=e.id,
            rule_name="off_hours_login",
            mitre_technique_id="T1078",
            mitre_technique_name="Valid Accounts",
            severity=Severity.low,
            description=(
                f"Successful login for user '{e.username}' from {e.src_ip} "
                f"at {e.timestamp} (outside normal 05:00-24:00 hours)."
            ),
            src_ip=e.src_ip,
            enrichment=get_ip_reputation(e.src_ip),
        ))
        created += 1

    return created


DETECTION_RULES = [
    detect_brute_force,
    detect_web_scanning,
    detect_off_hours_login,
    detect_kerberos,
]


def run_detection(db: Session, batch_limit: int = 2000) -> int:
    """
    Entry point for POST /detect/run. Pulls unprocessed LogEvents, runs
    every rule against that batch, marks them processed, and returns how
    many new Alert rows were created.
    """
    events = (
        db.query(LogEvent)
        .filter(LogEvent.processed_for_detection.is_(False))
        .order_by(LogEvent.timestamp.asc())
        .limit(batch_limit)
        .all()
    )
    if not events:
        return 0

    new_alerts = sum(rule(db, events) for rule in DETECTION_RULES)

    for e in events:
        e.processed_for_detection = True

    db.commit()
    return new_alerts
