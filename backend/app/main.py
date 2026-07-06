"""
SentinelHub API - main application entrypoint.

Run locally with:
    uvicorn app.main:app --reload

On startup, we create tables if they don't exist yet. For a real project
you'd switch to Alembic migrations once the schema stabilizes -- worth
mentioning in your README/interview as a "next step" to show you know
the difference between prototyping and production practice.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import Base, engine
from app.api import ingestion, logs, detection, alerts

app = FastAPI(
    title="SentinelHub API",
    description="A self-built SOC platform: log ingestion, detection, and threat intel enrichment.",
    version="0.1.0",
)

# Allow the React dashboard (running on a different port) to call this API.
# 3001 is the Dockerized frontend (docker-compose.yml), 5173 is Vite's
# default dev server port when running `npm run dev` outside Docker.
# Tighten this to specific origins before deploying publicly.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3001", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingestion.router)
app.include_router(logs.router)
app.include_router(detection.router)
app.include_router(alerts.router)


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)


@app.get("/")
def root():
    return {"status": "ok", "service": "sentinelhub-api"}


@app.get("/health")
def health():
    return {"status": "healthy"}
