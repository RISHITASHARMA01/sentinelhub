"""
Log Query API
-------------
Basic endpoints to read back what's been ingested. This is what the
dashboard (built in a later phase) will call. Kept simple for now:
list with filters + pagination.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime, timedelta
from pydantic import BaseModel
import uuid

from app.core.database import get_db
from app.models.models import LogEvent

router = APIRouter(prefix="/logs", tags=["logs"])


class LogEventOut(BaseModel):
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


@router.get("/", response_model=List[LogEventOut])
def list_logs(
    src_ip: Optional[str] = None,
    event_type: Optional[str] = None,
    q: Optional[str] = Query(None, description="Free-text search over the raw log line"),
    limit: int = Query(50, le=500),
    offset: int = 0,
    db: Session = Depends(get_db),
):
    query = db.query(LogEvent)
    if src_ip:
        query = query.filter(LogEvent.src_ip == src_ip)
    if event_type:
        query = query.filter(LogEvent.event_type == event_type)
    if q:
        query = query.filter(LogEvent.raw_message.ilike(f"%{q}%"))

    return (
        query.order_by(LogEvent.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/stats/summary")
def logs_summary(db: Session = Depends(get_db)):
    """Quick counts, useful for a dashboard header widget."""
    total = db.query(LogEvent).count()
    auth_failures = db.query(LogEvent).filter(LogEvent.event_type == "auth_failure").count()
    unique_ips = db.query(LogEvent.src_ip).distinct().count()

    return {
        "total_events": total,
        "auth_failures": auth_failures,
        "unique_source_ips": unique_ips,
    }


@router.get("/stats/timeseries")
def logs_timeseries(hours: int = Query(168, le=720), db: Session = Depends(get_db)):
    """
    Event counts bucketed by hour, for the Overview page's time-series
    chart. Defaults to a 7-day window (le=720/30 days max) rather than a
    tighter one, since demo/sample data often sits for a while between
    being loaded and being shown off in an interview.
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    bucket = func.date_trunc("hour", LogEvent.timestamp).label("bucket")

    rows = (
        db.query(bucket, func.count().label("count"))
        .filter(LogEvent.timestamp >= since)
        .group_by(bucket)
        .order_by(bucket)
        .all()
    )
    return [{"bucket": r.bucket.isoformat(), "count": r.count} for r in rows]
