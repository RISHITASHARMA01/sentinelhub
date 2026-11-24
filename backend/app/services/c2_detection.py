"""Passive network anomaly detection."""

from collections import defaultdict
from statistics import mean, pstdev

from app.models.models import Severity
from app.services.kerberos_detection import add_alert


def detect_c2(db, events):
    created = 0
    connections = defaultdict(list)

    for event in events:
        fields = event.parsed_fields or {}

        if fields.get("channel") != \
                "Microsoft-Windows-Sysmon/Operational":
            continue

        event_id = fields.get("event_id")

        if event_id == 3 and event.dest_ip:
            key = (
                event.source_host,
                event.dest_ip,
                str(fields.get("DestinationPort", "")),
                str(fields.get("Image", "")).lower(),
            )

            connections[key].append(event)

        elif event_id == 22:
            query = str(fields.get("QueryName", ""))
            labels = query.rstrip(".").split(".")

            if any(len(label) >= 50 for label in labels):
                add_alert(
                    db, event,
                    "unusual_dns_query",
                    "T1071.004",
                    "DNS",
                    "Unusually long DNS label observed. "
                    "Review application and DNS context.",
                    Severity.medium,
                )
                created += 1

    for key, group in connections.items():
        if len(group) < 6:
            continue

        group.sort(key=lambda e: e.timestamp)

        intervals = [
            (group[i].timestamp -
             group[i - 1].timestamp).total_seconds()
            for i in range(1, len(group))
        ]

        average = mean(intervals)

        if (
            average > 0
            and pstdev(intervals) / average <= 0.10
        ):
            add_alert(
                db, group[-1],
                "potential_network_beaconing",
                "T1071",
                "Application Layer Protocol",
                "Regular outbound connection pattern "
                "observed. Investigate destination and process.",
                Severity.medium,
            )
            created += 1

    return created
