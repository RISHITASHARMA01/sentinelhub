FROM python:3.11-slim

WORKDIR /app

COPY requirements*.txt ./

# INSTALL_DEV pulls in requirements-dev.txt (pytest) for local development
# via docker-compose (which passes INSTALL_DEV=true), so `docker compose
# exec backend pytest` works. The default build -- what CI and any real
# deploy uses -- leaves it out, keeping the shipped image free of test
# tooling.
ARG INSTALL_DEV=false
RUN pip install --no-cache-dir -r requirements.txt && \
    if [ "$INSTALL_DEV" = "true" ]; then pip install --no-cache-dir -r requirements-dev.txt; fi

COPY . .

# Run as a non-root user (UID 1000 matches the default first Linux user,
# so the docker-compose dev bind mount ./backend:/app stays readable
# without extra chown gymnastics on most machines).
RUN useradd --uid 1000 --create-home appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Shell form (not the JSON/exec form) so $PORT actually gets substituted --
# PaaS providers like Render inject PORT at runtime and expect the app to
# bind to it; locally it falls back to 8000 to match docker-compose.yml.
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
