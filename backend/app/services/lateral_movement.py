"""Defensive lateral movement indicators."""

from collections import defaultdict
from datetime import timedelta

from app.models.models import Severity
from app.services.kerberos_detection import add_alert


def detect_lateral_movement(db, events):
    created = 0
    remote_logins = defaultdict(list)

    for event in events:
        fields = event.parsed_fields or {}

        if fields.get("channel") != "Security":
            continue

        event_id = fields.get("event_id")
        logon_type = str(fields.get("LogonType", ""))

        if event_id == 4624 and event.src_ip:
            if logon_type == "10":
                add_alert(
                    db, event,
                    "remote_rdp_login",
                    "T1021.001",
                    "Remote Desktop Protocol",
                    "Remote interactive login observed. "
                    "Review source and account authorization.",
                    Severity.low,
                )
                created += 1

            if logon_type in ("3", "10") and event.username:
                remote_logins[
                    (event.username, event.src_ip)
                ].append(event)

        elif event_id in (5140, 5145):
            share = str(
                fields.get("ShareName", "")
            ).upper().split("\\")[-1]

            if share in ("ADMIN$", "C$"):
                add_alert(
                    db, event,
                    "administrative_share_access",
                    "T1021.002",
                    "SMB/Windows Admin Shares",
                    "Administrative share access observed.",
                    Severity.medium,
                )
                created += 1

        elif event_id == 4648:
            target = str(
                fields.get("TargetServerName", "")
            ).lower()

            if target not in ("", "-", "localhost",
                              str(event.source_host).lower()):
                add_alert(
                    db, event,
                    "remote_explicit_credentials",
                    "T1078",
                    "Valid Accounts",
                    "Explicit credentials used for a "
                    "potentially remote target.",
                    Severity.medium,
                )
                created += 1

        elif event_id == 4697 and event.src_ip:
            add_alert(
                db, event,
                "potential_remote_service_installation",
                "T1569.002",
                "Service Execution",
                "Service installation with remote-source "
                "context. Requires investigation.",
                Severity.medium,
            )
            created += 1

    for key, group in remote_logins.items():
        group.sort(key=lambda e: e.timestamp)

        for index, event in enumerate(group):
            window = [
                e for e in group[:index + 1]
                if event.timestamp - e.timestamp
                <= timedelta(minutes=5)
            ]

            hosts = {
                e.source_host for e in window
                if e.source_host
            }

            if len(hosts) >= 3:
                add_alert(
                    db, event,
                    "multi_host_remote_login",
                    "T1021",
                    "Remote Services",
                    f"Remote logins across {len(hosts)} "
                    f"hosts by account {key[0]}.",
                    Severity.high,
                )
                created += 1
                break

    return created
