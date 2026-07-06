"""
Alerts API
----------
Read access to what the detection engine has found, plus a manual threat
intel enrichment trigger. Alert *creation* happens in detection.py via
run_detection() (which also auto-enriches new alerts); status changes like
"investigating" / "resolved" are added in Phase 4 once there's a dashboard
UI driving them.
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.core.database import get_db
from app.models.models import Alert
from app.services.threat_intel import get_ip_reputation

router = APIRouter(prefix="/alerts", tags=["alerts"])


class TriggeringEventOut(BaseModel):
    """The single LogEvent that tripped the rule -- shown when a dashboard
    row is expanded so an analyst can see the raw evidence, not just our
    summary of it."""
    id: uuid.UUID
    source: str
    source_host: Optional[str]
    src_ip: Optional[str]
    username: Optional[str]
    event_type: Optional[str]
    raw_message: str
    timestamp: datetime

    class Config:
        from_attributes = True


class AlertOut(BaseModel):
    id: uuid.UUID
    triggering_event_id: Optional[uuid.UUID]
    triggering_event: Optional[TriggeringEventOut] = None
    rule_name: str
    mitre_technique_id: Optional[str]
    mitre_technique_name: Optional[str]
    severity: str
    description: str
    status: str
    src_ip: Optional[str]
    created_at: datetime
    enrichment: Optional[Any] = None  # populated once Phase 3 threat intel lands

    class Config:
        from_attributes = True


ALERT_STATUSES = {"open", "investigating", "resolved", "false_positive"}


@router.get("/", response_model=List[AlertOut])
def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    src_ip: Optional[str] = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
    db: Session = Depends(get_db),
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if src_ip:
        query = query.filter(Alert.src_ip == src_ip)

    return (
        query.order_by(Alert.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/stats/summary")
def alerts_summary(db: Session = Depends(get_db)):
    """
    Header-widget counts for the Overview page: total/open alert counts,
    a severity breakdown for the pie/bar chart, and how many distinct IPs
    have triggered an alert (a tighter, more meaningful "attacker count"
    than counting every IP that ever showed up in a log line).
    """
    total = db.query(Alert).count()
    open_count = db.query(Alert).filter(Alert.status == "open").count()
    unique_attacker_ips = db.query(Alert.src_ip).filter(Alert.src_ip.isnot(None)).distinct().count()

    severity_rows = db.query(Alert.severity, func.count()).group_by(Alert.severity).all()
    by_severity = {severity.value: count for severity, count in severity_rows}

    return {
        "total_alerts": total,
        "open_alerts": open_count,
        "unique_attacker_ips": unique_attacker_ips,
        "by_severity": by_severity,
    }


@router.get("/stats/timeseries")
def alerts_timeseries(hours: int = Query(168, le=720), db: Session = Depends(get_db)):
    """Alert counts bucketed by hour -- paired with logs_timeseries() on the
    Overview page's combined events-vs-alerts chart."""
    since = datetime.utcnow() - timedelta(hours=hours)
    bucket = func.date_trunc("hour", Alert.created_at).label("bucket")

    rows = (
        db.query(bucket, func.count().label("count"))
        .filter(Alert.created_at >= since)
        .group_by(bucket)
        .order_by(bucket)
        .all()
    )
    return [{"bucket": r.bucket.isoformat(), "count": r.count} for r in rows]


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: uuid.UUID, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


class AlertStatusUpdate(BaseModel):
    status: str


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert_status(alert_id: uuid.UUID, payload: AlertStatusUpdate, db: Session = Depends(get_db)):
    """Move an alert through the analyst workflow: open -> investigating ->
    resolved / false_positive. Driven by the dashboard's case view."""
    if payload.status not in ALERT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of {sorted(ALERT_STATUSES)}",
        )

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = payload.status
    db.commit()
    db.refresh(alert)
    return alert


class EnrichResult(BaseModel):
    enriched: bool
    alert: AlertOut


@router.post("/{alert_id}/enrich", response_model=EnrichResult)
def enrich_alert(alert_id: uuid.UUID, db: Session = Depends(get_db)):
    """
    Manually (re-)run threat intel lookup for an alert. Alerts are already
    auto-enriched when the detection engine creates them -- this exists for
    cases where enrichment was skipped at creation time (e.g. no API key
    configured yet) or you want a fresher lookup than what's cached.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if not alert.src_ip:
        return EnrichResult(enriched=False, alert=alert)

    reputation = get_ip_reputation(alert.src_ip)
    if reputation is None:
        return EnrichResult(enriched=False, alert=alert)

    alert.enrichment = reputation
    db.commit()
    db.refresh(alert)
    return EnrichResult(enriched=True, alert=alert)
