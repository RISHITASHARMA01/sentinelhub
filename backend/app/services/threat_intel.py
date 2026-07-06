"""
Threat Intelligence Enrichment
-------------------------------
Cross-references an alert's src_ip against AbuseIPDB's free-tier API to
answer "have other people already seen this IP behaving badly?" -- turning
a bare IP address into something an analyst can act on immediately (abuse
score, country, ISP, how many times it's been reported elsewhere).

Design choices worth explaining in an interview:
  - A missing API key never crashes the app -- enrichment is a nice-to-have
    layered on top of detection, not something the pipeline should depend on.
  - A simple in-memory TTL cache avoids burning the free tier's daily quota
    re-checking the same repeat-offender IP every time it triggers an alert.
  - Network errors (timeout, rate limit, bad response) are caught and
    logged, never raised -- one flaky API call should never break alert
    creation or block a request.
"""

import os
import time
import logging
from typing import Optional, Dict, Any, Tuple

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("sentinelhub.threat_intel")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
REQUEST_TIMEOUT_SECONDS = 5
CACHE_TTL_SECONDS = 60 * 60  # 1 hour -- free tier quota is limited, no need to re-check more often

# In-memory cache: {ip: (fetched_at_epoch_seconds, result_dict)}
_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}


def _get_from_cache(ip: str) -> Optional[Dict[str, Any]]:
    entry = _cache.get(ip)
    if not entry:
        return None
    fetched_at, data = entry
    if time.time() - fetched_at > CACHE_TTL_SECONDS:
        return None
    return data


def get_ip_reputation(ip: str) -> Optional[Dict[str, Any]]:
    """
    Returns a small dict of AbuseIPDB fields, or None if enrichment isn't
    possible right now (no API key configured, network error, rate limit,
    etc). Deliberately never raises -- callers should treat "no enrichment"
    as a normal outcome, not a failure.
    """
    if not ip:
        return None

    cached = _get_from_cache(ip)
    if cached is not None:
        return cached

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        logger.warning("ABUSEIPDB_API_KEY not set -- skipping enrichment for %s", ip)
        return None

    try:
        response = httpx.get(
            ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return None

    payload = response.json().get("data", {})
    result = {
        "source": "abuseipdb",
        "abuse_score": payload.get("abuseConfidenceScore"),
        "country": payload.get("countryCode"),
        "isp": payload.get("isp"),
        "domain": payload.get("domain"),
        "total_reports": payload.get("totalReports"),
        "last_reported_at": payload.get("lastReportedAt"),
        "fetched_at": time.time(),
    }
    _cache[ip] = (time.time(), result)
    return result
