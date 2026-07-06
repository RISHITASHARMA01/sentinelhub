# Deploying SentinelHub

This guide deploys the three services (Postgres, backend, frontend) to
**Render**. Render was chosen over Railway for this project because its
free tier includes both a free Postgres instance and a free web service
tier without requiring a paid plan up front — Railway's free tier was
discontinued in favor of a small one-time trial credit, which doesn't
suit a long-lived portfolio project you want to keep demo-ready. Worth
naming as a trade-off in an interview: Render's free Postgres expires
after 90 days and has to be recreated (and its `DATABASE_URL` re-wired
into the backend service) — fine for a portfolio piece you're actively
demoing, not something you'd accept for production.

## 1. Push the repo to GitHub

```bash
git remote add origin https://github.com/<you>/sentinelhub.git
git push -u origin main
```

## 2. Create the Postgres database

1. Render dashboard → **New** → **PostgreSQL**.
2. Name: `sentinelhub-db`. Plan: **Free**.
3. Once created, copy the **Internal Database URL** (starts with
   `postgresql://...`) — you'll need it in the next step. Use the
   *internal* URL, not the external one: the backend talks to Postgres
   from inside Render's network, so it doesn't need to leave it.

## 3. Deploy the backend

1. Render dashboard → **New** → **Web Service** → connect your GitHub repo.
2. **Root Directory**: `backend`
3. **Environment**: `Docker` (Render builds `backend/Dockerfile` directly —
   no build/start command needed; the Dockerfile's `CMD` already reads the
   `$PORT` Render injects at runtime).
4. **Environment Variables**:
   - `DATABASE_URL` = the internal Postgres URL from step 2
   - `ABUSEIPDB_API_KEY` = your AbuseIPDB key (optional — omit it and
     enrichment just skips itself, per `backend/app/services/threat_intel.py`)
5. Deploy. Once live, note the backend's public URL
   (`https://sentinelhub-backend-xxxx.onrender.com`).
6. Update `backend/app/main.py`'s CORS `allow_origins` to include your
   frontend's eventual Render URL (step 4 below) and redeploy — or set it
   from an environment variable if you'd rather not hardcode it per
   deploy (a reasonable Phase 7 improvement to mention in an interview).

## 4. Deploy the frontend

Deploy this one as a **Static Site** rather than the Docker image —
simpler and free on Render, and the nginx container in
`frontend/Dockerfile` is really only there to demonstrate the containerized
path for local Docker Compose use.

1. Render dashboard → **New** → **Static Site** → connect your GitHub repo.
2. **Root Directory**: `frontend`
3. **Build Command**: `npm install && npm run build`
4. **Publish Directory**: `dist`
5. **Environment Variables**: `VITE_API_URL` = the backend's public URL
   from step 3.5 (Vite bakes this into the JS bundle at build time, so it
   must be set *before* the build runs, not after).
6. **Redirects/Rewrites**: add a rule `/*` → `/index.html` (rewrite, not
   redirect) so client-side routes like `/alerts` don't 404 on a
   hard refresh — same reason `frontend/nginx.conf` has a `try_files`
   fallback for the Docker path.

## 5. Verify

```bash
curl https://sentinelhub-backend-xxxx.onrender.com/health
```
Then open the frontend's Render URL and confirm the dashboard loads and
can reach the backend (check the browser console for CORS errors — that
almost always means step 3.6 was missed).

## Notes for the free tier

- Free web services on Render spin down after periods of inactivity and
  take ~30-60s to cold-start on the next request — expected, not a bug,
  when demoing after it's been idle.
- Free Postgres instances expire after 90 days. When that happens: create
  a new one, update `DATABASE_URL` on the backend service, and re-ingest
  `docs/sample_auth.log` + re-run detection to repopulate demo data.
