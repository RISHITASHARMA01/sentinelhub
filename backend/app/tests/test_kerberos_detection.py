from unittest.mock import MagicMock
from types import SimpleNamespace
from datetime import datetime, timedelta
from uuid import uuid4

from app.services.kerberos_detection import detect_kerberos


def event(event_id, offset=0, **fields):
    return SimpleNamespace(
        id=uuid4(),
        timestamp=datetime(2026, 1, 1) + timedelta(seconds=offset),
        source_host="LAB-DC",
        src_ip="192.0.2.10",
        username="lab_user",
        parsed_fields={
            "event_id": event_id,
            "channel": "Security",
            **fields,
        },
    )


def test_kerberoasting_indicator():
    db = MagicMock()
    events = [event(4769, TicketEncryptionType="0x17")]
    assert detect_kerberos(db, events) == 1
    assert db.add.call_args.args[0].rule_name == \
        "potential_kerberoasting"


def test_asrep_indicator():
    db = MagicMock()
    events = [event(4768, PreAuthType="0", Status="0x0")]
    assert detect_kerberos(db, events) == 1


def test_failure_burst():
    db = MagicMock()
    events = [event(4771, i) for i in range(6)]
    assert detect_kerberos(db, events) == 1


def test_ticket_volume():
    db = MagicMock()
    events = [
        event(4769, i, ServiceName=f"service-{i}",
              TicketEncryptionType="0x12")
        for i in range(6)
    ]
    assert detect_kerberos(db, events) == 1


def test_normal_ticket():
    db = MagicMock()
    events = [event(4769, TicketEncryptionType="0x12")]
    assert detect_kerberos(db, events) == 0


def test_normal_preauth():
    db = MagicMock()
    events = [event(4768, PreAuthType="2", Status="0x0")]
    assert detect_kerberos(db, events) == 0


def test_failures_outside_window():
    db = MagicMock()
    events = [event(4771, i * 120) for i in range(6)]
    assert detect_kerberos(db, events) == 0
