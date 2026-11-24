"""Persistence and defense-evasion indicators."""

from app.models.models import Severity
from app.services.kerberos_detection import add_alert


def detect_persistence(db, events):
    created = 0

    rules = {
        4698: (
            "scheduled_task_created",
            "T1053.005",
            "Scheduled Task",
            Severity.medium,
        ),
        4697: (
            "service_installation",
            "T1543.003",
            "Windows Service",
            Severity.medium,
        ),
        4720: (
            "new_account_created",
            "T1136",
            "Create Account",
            Severity.low,
        ),
        1102: (
            "security_log_cleared",
            "T1070.001",
            "Clear Windows Event Logs",
            Severity.high,
        ),
    }

    for event in events:
        fields = event.parsed_fields or {}
        event_id = fields.get("event_id")
        channel = fields.get("channel")

        if channel == "Security" and event_id in rules:
            rule, technique, name, severity = rules[event_id]

            add_alert(
                db, event,
                rule, technique, name,
                f"{name} indicator observed on "
                f"{event.source_host}. Review authorization.",
                severity,
            )
            created += 1

        elif (
            channel == "Microsoft-Windows-Sysmon/Operational"
            and event_id in (12, 13, 14)
        ):
            target = str(
                fields.get("TargetObject", "")
            ).lower()

            markers = (
                "\\currentversion\\run\\",
                "\\currentversion\\runonce\\",
                "\\currentversion\\run",
                "\\currentversion\\runonce",
            )

            if any(
                target.endswith(m.rstrip("\\"))
                or m.rstrip("\\") + "\\" in target
                for m in markers
            ):
                add_alert(
                    db, event,
                    "startup_registry_modification",
                    "T1547.001",
                    "Registry Run Keys / Startup Folder",
                    "Startup registry modification observed.",
                    Severity.high,
                )
                created += 1

    return created
