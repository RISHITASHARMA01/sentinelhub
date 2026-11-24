from unittest.mock import MagicMock
from types import SimpleNamespace
from datetime import datetime, timedelta
from uuid import uuid4

from app.services.lateral_movement import (
    detect_lateral_movement
)


def event(event_id, host="LAB-PC", offset=0, **fields):
    return SimpleNamespace(
        id=uuid4(),
        timestamp=datetime(2026, 1, 1) + timedelta(seconds=offset),
        source_host=host,
        src_ip="192.0.2.40",
        username="lab_user",
        parsed_fields={
            "event_id": event_id,
            "channel": "Security",
            **fields,
        },
    )


def test_rdp_login():
    db = MagicMock()
    assert detect_lateral_movement(
        db, [event(4624, LogonType="10")]
    ) == 1


def test_admin_share():
    db = MagicMock()
    assert detect_lateral_movement(
        db, [event(5140, ShareName="ADMIN$")]
    ) == 1


def test_explicit_credentials():
    db = MagicMock()
    assert detect_lateral_movement(
        db, [event(4648, TargetServerName="LAB-SERVER")]
    ) == 1


def test_remote_service():
    db = MagicMock()
    assert detect_lateral_movement(
        db, [event(4697, ServiceName="LabService")]
    ) == 1


def test_multi_host_login():
    db = MagicMock()
    events = [
        event(4624, host=f"LAB-PC-{i}",
              offset=i * 10, LogonType="3")
        for i in range(3)
    ]
    assert detect_lateral_movement(db, events) == 1


def test_normal_local_login():
    db = MagicMock()
    assert detect_lateral_movement(
        db, [event(4624, LogonType="2")]
    ) == 0


def test_normal_share():
    db = MagicMock()
    assert detect_lateral_movement(
        db, [event(5140, ShareName="Documents")]
    ) == 0


def test_multi_host_outside_window():
    db = MagicMock()
    events = [
        event(4624, host=f"LAB-PC-{i}",
              offset=i * 600, LogonType="3")
        for i in range(3)
    ]
    assert detect_lateral_movement(db, events) == 0


def test_local_explicit_credentials():
    db = MagicMock()
    assert detect_lateral_movement(
        db, [event(4648, TargetServerName="localhost")]
    ) == 0
