"""Defensive Kerberos anomaly detection rules."""

from collections import defaultdict
from datetime import timedelta

from app.models.models import Alert, Severity


def numeric(value):
    try:
        return int(str(value), 0)
    except (ValueError, TypeError):
        return None


def add_alert(db, event, rule, technique, name,
              description, severity):

    fields = event.parsed_fields or {}

    db.add(Alert(
        triggering_event_id=event.id,
        rule_name=rule,
        mitre_technique_id=technique,
        mitre_technique_name=name,
        severity=severity,
        description=description,
        src_ip=event.src_ip,
        enrichment={
            "hostname": event.source_host,
            "username": event.username,
            "event_id": fields.get("event_id"),
            "synthetic": fields.get("synthetic", False),
        },
    ))


def detect_kerberos(db, events):
    created = 0
    failures = defaultdict(list)
    tickets = defaultdict(list)

    for event in events:
        fields = event.parsed_fields or {}

        if fields.get("channel") != "Security":
            continue

        event_id = fields.get("event_id")

        # Legacy encryption indicator.
        if event_id == 4769:
            encryption = numeric(
                fields.get("TicketEncryptionType")
            )

            if encryption == 23:
                add_alert(
                    db, event,
                    "potential_kerberoasting",
                    "T1558.003",
                    "Kerberoasting",
                    "Legacy RC4 service ticket observed. "
                    "Investigate account and service context.",
                    Severity.medium,
                )
                created += 1

            if event.username and event.src_ip:
                tickets[
                    (event.username, event.src_ip)
                ].append(event)

        # Authentication without pre-authentication.
        elif event_id == 4768:
            preauth = numeric(fields.get("PreAuthType"))
            status = numeric(fields.get("Status"))

            if preauth == 0 and status == 0:
                add_alert(
                    db, event,
                    "potential_asrep_roasting",
                    "T1558.004",
                    "AS-REP Roasting",
                    "Successful TGT request without "
                    "Kerberos pre-authentication.",
                    Severity.medium,
                )
                created += 1

        elif event_id == 4771 and event.src_ip:
            failures[event.src_ip].append(event)

    # Authentication failure correlation.
    for ip, group in failures.items():
        group.sort(key=lambda e: e.timestamp)

        for index, event in enumerate(group):
            window = [
                e for e in group[:index + 1]
                if event.timestamp - e.timestamp
                <= timedelta(seconds=60)
            ]

            if len(window) >= 5:
                add_alert(
                    db, event,
                    "kerberos_failure_burst",
                    "T1110",
                    "Brute Force",
                    f"Repeated Kerberos authentication "
                    f"failures from {ip}.",
                    Severity.medium,
                )
                created += 1
                break

    # Service ticket volume correlation.
    for key, group in tickets.items():
        group.sort(key=lambda e: e.timestamp)

        for index, event in enumerate(group):
            window = [
                e for e in group[:index + 1]
                if event.timestamp - e.timestamp
                <= timedelta(minutes=5)
            ]

            services = {
                (e.parsed_fields or {}).get("ServiceName")
                for e in window
            } - {None, ""}

            if len(services) >= 5:
                add_alert(
                    db, event,
                    "unusual_kerberos_ticket_volume",
                    "T1558.003",
                    "Kerberoasting",
                    "Unusual volume of distinct Kerberos "
                    "service ticket requests.",
                    Severity.high,
                )
                created += 1
                break

    return created
