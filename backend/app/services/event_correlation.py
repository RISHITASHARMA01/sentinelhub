"""Host-based security event correlation."""

from collections import defaultdict
from datetime import timedelta

from app.models.models import Severity
from app.services.kerberos_detection import add_alert


CATEGORIES = {
    "special_privileges": "privilege",
    "user_right_assigned": "privilege",
    "group_member_added": "account",
    "user_created": "account",
    "scheduled_task_creation": "persistence",
    "service_installation": "persistence",
    "registry_modification": "registry",
    "audit_log_cleared": "defense_evasion",
}


def detect_correlated_activity(db, events):
    groups = defaultdict(list)
    created = 0

    for event in events:
        if (
            event.source_host
            and event.event_type in CATEGORIES
        ):
            fields = event.parsed_fields or {}
            key = (
                event.source_host,
                fields.get("synthetic", False),
            )
            groups[key].append(event)

    for key, group in groups.items():
        group.sort(key=lambda e: e.timestamp)

        for index, event in enumerate(group):
            window = [
                e for e in group[:index + 1]
                if event.timestamp - e.timestamp
                <= timedelta(minutes=10)
            ]

            categories = {
                CATEGORIES[e.event_type]
                for e in window
            }

            score = min(100, len(categories) * 25)

            if score >= 75:
                add_alert(
                    db, event,
                    "correlated_security_activity",
                    None,
                    "Multi-category security activity",
                    f"Host {key[0]} produced multiple "
                    f"security indicators. Risk score: "
                    f"{score}/100. Categories: "
                    + ", ".join(sorted(categories)),
                    Severity.high,
                )
                created += 1
                break

    return created
