"""Privilege escalation indicators."""

from app.models.models import Severity
from app.services.kerberos_detection import add_alert

SENSITIVE_PRIVILEGES = {
    "SeDebugPrivilege",
    "SeTcbPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
}

ADMIN_GROUPS = {
    "administrators",
    "domain admins",
    "enterprise admins",
    "schema admins",
}


def detect_privilege_escalation(db, events):
    created = 0

    for event in events:
        fields = event.parsed_fields or {}

        if fields.get("channel") != "Security":
            continue

        event_id = fields.get("event_id")

        if event_id == 4672:
            privileges = set(
                str(fields.get("PrivilegeList", "")).split()
            )

            sensitive = privileges & SENSITIVE_PRIVILEGES

            if sensitive:
                add_alert(
                    db, event,
                    "sensitive_privilege_assignment",
                    "T1078",
                    "Valid Accounts",
                    "Sensitive privileges observed: "
                    + ", ".join(sorted(sensitive)),
                    Severity.medium,
                )
                created += 1

        elif event_id in (4728, 4732, 4756):
            group = str(
                fields.get("TargetUserName", "")
            ).lower()

            sid = str(fields.get("TargetSid", ""))

            if (
                group in ADMIN_GROUPS
                or sid == "S-1-5-32-544"
                or sid.endswith(("-512", "-518", "-519"))
            ):
                add_alert(
                    db, event,
                    "administrative_group_modification",
                    "T1098.007",
                    "Additional Local or Domain Groups",
                    f"Administrative group modified: {group}",
                    Severity.high,
                )
                created += 1

        elif event_id == 4704:
            rights = set(
                str(fields.get("PrivilegeList", "")).split()
            )

            if rights & SENSITIVE_PRIVILEGES:
                add_alert(
                    db, event,
                    "sensitive_user_right_assigned",
                    "T1098",
                    "Account Manipulation",
                    "Sensitive user right assigned.",
                    Severity.high,
                )
                created += 1

    return created
