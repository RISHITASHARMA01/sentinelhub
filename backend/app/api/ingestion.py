"""
Ingestion API
-------------
Two ways to get logs in:
  1. POST /ingest/line  - push a single raw log line (good for testing, or
     for a lightweight agent that tails a file and posts each new line)
  2. POST /ingest/file  - upload a whole log file to bulk-load sample data

Both paths run the line through our parser and store a LogEvent row.
Lines that fail to parse are counted and reported back, not silently
dropped, so you can see ingestion health.
"""

from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from app.core.database import get_db
from app.models.models import LogEvent
from app.services.log_parser import parse_log_line

router = APIRouter(prefix="/ingest", tags=["ingestion"])


class RawLogLine(BaseModel):
    line: str
    source_hint: Optional[str] = "auto"  # "system", "web_server", or "auto"


class IngestResult(BaseModel):
    parsed: int
    skipped: int
    total: int


@router.post("/line", response_model=IngestResult)
def ingest_line(payload: RawLogLine, db: Session = Depends(get_db)):
    parsed = parse_log_line(payload.line, payload.source_hint)
    if parsed is None:
        return IngestResult(parsed=0, skipped=1, total=1)

    event = LogEvent(**parsed)
    db.add(event)
    db.commit()
    return IngestResult(parsed=1, skipped=0, total=1)


@router.post("/file", response_model=IngestResult)
async def ingest_file(
    source_hint: str = "auto",
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    content = (await file.read()).decode("utf-8", errors="ignore")
    lines = [l for l in content.splitlines() if l.strip()]

    parsed_count = 0
    skipped_count = 0
    events_to_add = []

    for line in lines:
        parsed = parse_log_line(line, source_hint)
        if parsed is None:
            skipped_count += 1
            continue
        events_to_add.append(LogEvent(**parsed))
        parsed_count += 1

    if events_to_add:
        db.bulk_save_objects(events_to_add)
        db.commit()

    return IngestResult(parsed=parsed_count, skipped=skipped_count, total=len(lines))
