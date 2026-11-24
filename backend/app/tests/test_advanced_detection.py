import json
from unittest.mock import MagicMock
from types import SimpleNamespace
from uuid import uuid4

from app.services.windows_parser import parse_windows_log_line
from app.services.adversary_simulator import generate_events
from app.services.privilege_escalation import detect_privilege_escalation
from app.services.persistence_detection import detect_persistence
from app.services.c2_detection import detect_c2
from app.services.event_correlation import detect_correlated_activity


def events():
    result = []

    for raw in generate_events():
        parsed = parse_windows_log_line(json.dumps(raw))
        assert parsed is not None

        result.append(
            SimpleNamespace(id=uuid4(), **parsed)
        )

    return result


def test_simulation_event_count():
    assert len(generate_events()) == 17


def test_simulation_parsing():
    assert len(events()) == 17


def test_simulation_labels():
    assert all(
        e.parsed_fields["synthetic"]
        for e in events()
    )


def test_privilege_escalation():
    db = MagicMock()
    assert detect_privilege_escalation(db, events()) == 3


def test_persistence():
    db = MagicMock()
    assert detect_persistence(db, events()) == 5


def test_c2_detection():
    db = MagicMock()
    assert detect_c2(db, events()) == 2


def test_event_correlation():
    db = MagicMock()
    assert detect_correlated_activity(db, events()) == 1


def test_empty_events():
    db = MagicMock()

    for detector in (
        detect_privilege_escalation,
        detect_persistence,
        detect_c2,
        detect_correlated_activity,
    ):
        assert detector(db, []) == 0


def test_normal_network_event():
    db = MagicMock()

    network = [
        e for e in events()
        if e.event_type == "network_connection"
    ][:1]

    assert detect_c2(db, network) == 0


def test_normal_privilege():
    db = MagicMock()

    event = next(
        e for e in events()
        if e.event_type == "special_privileges"
    )

    event.parsed_fields["PrivilegeList"] = "SeChangeNotifyPrivilege"

    assert detect_privilege_escalation(db, [event]) == 0


def test_single_event_correlation():
    db = MagicMock()
    assert detect_correlated_activity(db, events()[:1]) == 0


def test_mitre_mapping():
    db = MagicMock()

    detect_privilege_escalation(db, events())

    for call in db.add.call_args_list:
        alert = call.args[0]
        assert alert.mitre_technique_id.startswith("T")
