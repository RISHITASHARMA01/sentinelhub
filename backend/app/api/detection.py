"""
Detection API
-------------
A single manual trigger endpoint for now. In a later phase this could be
replaced or supplemented by a background scheduler (APScheduler, or Celery
beat) that runs detection automatically every N seconds -- worth mentioning
as a "next step" in an interview to show you thought past the manual-trigger
prototype stage.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.core.database import get_db
from app.services.detection_engine import run_detection

router = APIRouter(prefix="/detect", tags=["detection"])


class DetectionResult(BaseModel):
    new_alerts: int


@router.post("/run", response_model=DetectionResult)
def trigger_detection(db: Session = Depends(get_db)):
    new_alerts = run_detection(db)
    return DetectionResult(new_alerts=new_alerts)
