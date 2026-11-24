import json
from app.services.windows_parser import parse_windows_log_line
from app.services.log_parser import parse_log_line


def sample_event():
    return {
        "EventID": 4624,
        "Channel": "Security",
        "Computer": "LAB-PC",
        "TimeCreated": "2026-11-24T10:00:00Z",
        "EventData": {
            "TargetUserName": "lab_user",
            "IpAddress": "192.0.2.10",
            "LogonType": "10",
        },
    }


def test_windows_login():
    result = parse_windows_log_line(json.dumps(sample_event()))
    assert result["event_type"] == "auth_success"
    assert result["username"] == "lab_user"
    assert result["source"] == "custom"
    assert result["parsed_fields"]["event_id"] == 4624


def test_kerberos_event():
    event = sample_event()
    event["EventID"] = 4769
    result = parse_windows_log_line(json.dumps(event))
    assert result["event_type"] == "kerberos_service_ticket"


def test_sysmon_network_event():
    event = sample_event()
    event["EventID"] = 3
    event["Channel"] = "Microsoft-Windows-Sysmon/Operational"
    result = parse_windows_log_line(json.dumps(event))
    assert result["event_type"] == "network_connection"


def test_invalid_json():
    assert parse_windows_log_line("invalid log") is None


def test_missing_fields():
    assert parse_windows_log_line("{}") is None


def test_auto_dispatch():
    result = parse_log_line(json.dumps(sample_event()), "auto")
    assert result["event_type"] == "auth_success"


def test_invalid_ip():
    event = sample_event()
    event["EventData"]["IpAddress"] = "-"
    result = parse_windows_log_line(json.dumps(event))
    assert result["src_ip"] is None
