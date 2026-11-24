"""Synthetic event simulation API."""

import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import LogEvent
from app.services.windows_parser import parse_windows_log_line
from app.services.adversary_simulator import generate_events

router = APIRouter(
    prefix="/simulation",
    tags=["simulation"],
)


@router.post("/run")
def run_simulation(db: Session = Depends(get_db)):
    events = generate_events()
    parsed = 0

    for event in events:
        normalized = parse_windows_log_line(
            json.dumps(event)
        )

        if normalized:
            db.add(LogEvent(**normalized))
            parsed += 1

    db.commit()

    return {
        "simulation": "completed",
        "synthetic": True,
        "events_generated": len(events),
        "events_ingested": parsed,
    }
