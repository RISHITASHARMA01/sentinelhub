"""Generate fictional security telemetry for SOC testing."""

import json
from datetime import datetime, timedelta, timezone


def generate_events():
    events = []
    now = datetime.now(timezone.utc)

    def add(event_id, fields, offset=0,
            channel="Security", host="LAB-PC"):

        events.append({
            "EventID": event_id,
            "Channel": channel,
            "Computer": host,
            "TimeCreated": (
                now + timedelta(seconds=offset)
            ).isoformat(),
            "Synthetic": True,
            "EventData": fields,
        })

    # Privilege indicators
    add(4672, {
        "SubjectUserName": "lab_user",
        "PrivilegeList": "SeDebugPrivilege",
    })

    add(4728, {
        "TargetUserName": "Domain Admins",
        "SubjectUserName": "lab_admin",
    })

    add(4704, {
        "SubjectUserName": "lab_admin",
        "PrivilegeList": "SeBackupPrivilege",
    })

    # Persistence indicators
    add(4698, {
        "SubjectUserName": "lab_user",
        "TaskName": "LabSimulationTask",
    })

    add(4697, {
        "ServiceName": "LabSimulationService",
        "SubjectUserName": "lab_user",
    })

    add(4720, {
        "TargetUserName": "lab_test_account",
    })

    add(1102, {
        "SubjectUserName": "lab_admin",
    })

    sysmon = "Microsoft-Windows-Sysmon/Operational"

    add(13, {
        "TargetObject": (
            r"HKLM\Software\Microsoft\Windows"
            r"\CurrentVersion\Run\LabSimulation"
        ),
    }, channel=sysmon)

    # Synthetic periodic network telemetry
    for i in range(8):
        add(3, {
            "SourceIp": "192.0.2.50",
            "DestinationIp": "198.51.100.50",
            "DestinationPort": "443",
            "Image": r"C:\Lab\simulator.exe",
        }, offset=i * 30, channel=sysmon)

    add(22, {
        "QueryName": "a" * 55 + ".simulation.example",
        "Image": r"C:\Lab\simulator.exe",
    }, channel=sysmon)

    return events


if __name__ == "__main__":
    for event in generate_events():
        print(json.dumps(event))
