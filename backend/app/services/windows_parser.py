"""Windows Security and Sysmon JSON event parser."""

import json
import ipaddress
from datetime import datetime, timezone

WINDOWS_EVENTS = {
    1102: "audit_log_cleared",
    4624: "auth_success",
    4625: "auth_failure",
    4648: "explicit_credentials",
    4672: "special_privileges",
    4688: "process_creation",
    4697: "service_installation",
    4698: "scheduled_task_creation",
    4704: "user_right_assigned",
    4720: "user_created",
    4728: "group_member_added",
    4732: "group_member_added",
    4756: "group_member_added",
    4768: "kerberos_tgt_request",
    4769: "kerberos_service_ticket",
    4771: "kerberos_preauth_failure",
    5140: "network_share_access",
    5145: "network_share_check",
}

SYSMON_EVENTS = {
    1: "process_creation",
    3: "network_connection",
    11: "file_creation",
    12: "registry_modification",
    13: "registry_modification",
    14: "registry_modification",
    22: "dns_query",
}


def normalize_ip(value):
    try:
        address = ipaddress.ip_address(str(value))
        return str(getattr(address, "ipv4_mapped", None) or address)
    except ValueError:
        return None


def parse_windows_log_line(line):
    try:
        event = json.loads(line)

        if not isinstance(event, dict):
            return None

        event_id = int(event["EventID"])
        channel = event.get("Channel", "Security")

        if channel == "Security":
            event_map = WINDOWS_EVENTS
        elif channel == "Microsoft-Windows-Sysmon/Operational":
            event_map = SYSMON_EVENTS
        else:
            return None

        fields = event.get("EventData", {})

        if not isinstance(fields, dict):
            return None

        timestamp = datetime.fromisoformat(
            event["TimeCreated"].replace("Z", "+00:00")
        )

        if timestamp.tzinfo:
            timestamp = timestamp.astimezone(
                timezone.utc
            ).replace(tzinfo=None)

        return {
            "source": "custom",
            "source_host": event.get("Computer"),
            "src_ip": normalize_ip(
                fields.get("IpAddress") or fields.get("SourceIp")
            ),
            "dest_ip": normalize_ip(
                fields.get("DestinationIp")
            ),
            "username": (
                fields.get("TargetUserName")
                or fields.get("SubjectUserName")
                or fields.get("User")
            ),
            "event_type": event_map.get(
                event_id, "windows_event"
            ),
            "raw_message": line.strip(),
            "timestamp": timestamp,
            "parsed_fields": {
                **fields,
                "event_id": event_id,
                "channel": channel,
                "platform": "windows",
                "synthetic": event.get("Synthetic") is True,
            },
        }

    except (ValueError, KeyError, TypeError, AttributeError):
        return None
