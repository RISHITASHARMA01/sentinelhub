"""
SentinelHub Database Models
-----------------------------
Three core tables to start:
  - LogEvent: raw normalized log entries from any source (system, web server, honeypot)
  - Alert: a detection engine finding, linked back to the log event(s) that triggered it
  - User: basic auth for the dashboard (analyst / admin roles)

We keep this intentionally simple at first. We'll add ThreatIntel and Case
management tables in a later phase once ingestion + detection are working.
"""

import uuid
import enum
from datetime import datetime

from sqlalchemy import (
    Column, String, DateTime, Integer, Text, ForeignKey, Enum, Boolean
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.core.database import Base


class Severity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class LogSource(str, enum.Enum):
    system = "system"          # OS / auth logs
    web_server = "web_server"  # nginx / apache
    honeypot = "honeypot"      # cowrie or similar
    custom = "custom"


class LogEvent(Base):
    """
    A normalized log entry. Whatever the raw source format is (syslog, JSON,
    Apache combined log format, etc.), the ingestion service parses it down
    to this common shape so the detection engine only has to reason about
    one schema, not five.
    """
    __tablename__ = "log_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source = Column(Enum(LogSource), nullable=False, index=True)
    source_host = Column(String(255), nullable=True)       # which machine/service emitted it
    src_ip = Column(String(45), nullable=True, index=True)  # supports IPv6 length
    dest_ip = Column(String(45), nullable=True)
    username = Column(String(255), nullable=True)
    event_type = Column(String(100), nullable=True, index=True)  # e.g. "auth_failure", "http_request"
    raw_message = Column(Text, nullable=False)
    parsed_fields = Column(JSONB, nullable=True)  # anything extra, source-specific
    timestamp = Column(DateTime, nullable=False, index=True)
    ingested_at = Column(DateTime, default=datetime.utcnow)

    # Detection engine marks an event True once it's been scanned by every
    # rule, so re-running /detect/run doesn't re-alert on the same events.
    processed_for_detection = Column(Boolean, default=False, nullable=False, index=True)

    alerts = relationship("Alert", back_populates="triggering_event")


class Alert(Base):
    """
    Output of the detection engine. Each alert references the log event
    that triggered it and (once we build that module) a MITRE ATT&CK
    technique ID, e.g. T1110 for brute force.
    """
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    triggering_event_id = Column(UUID(as_uuid=True), ForeignKey("log_events.id"), nullable=True)
    rule_name = Column(String(255), nullable=False)
    mitre_technique_id = Column(String(20), nullable=True)   # e.g. "T1110"
    mitre_technique_name = Column(String(255), nullable=True)
    severity = Column(Enum(Severity), nullable=False, default=Severity.medium)
    description = Column(Text, nullable=False)
    status = Column(String(50), default="open")  # open / investigating / resolved / false_positive
    src_ip = Column(String(45), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    enrichment = Column(JSONB, nullable=True)  # threat intel data added later

    triggering_event = relationship("LogEvent", back_populates="alerts")


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="analyst")  # analyst / admin
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
