"""Shared HTTP helper: timeouts, retries with backoff, per-host rate limiting,
and an on-disk JSON cache.  Stdlib only."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

log = logging.getLogger("faultline.http")

USER_AGENT = "FaultLine-PAVD/2.0 (+https://github.com/robotichackingcommunity/PA_VD)"
DEFAULT_TIMEOUT = 60
MAX_ATTEMPTS = 5


class RateLimiter:
    """Token bucket: at most `calls` requests per `period` seconds."""

    def __init__(self, calls: int, period: float):
        self.calls, self.period = calls, period
        self._stamps: list[float] = []
        self._lock = threading.Lock()

    def wait(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                self._stamps = [t for t in self._stamps if now - t < self.period]
                if len(self._stamps) < self.calls:
                    self._stamps.append(now)
                    return
                sleep_for = self.period - (now - self._stamps[0]) + 0.05
            time.sleep(max(sleep_for, 0.01))


_LIMITERS: dict[str, RateLimiter] = {}
_LIMITERS_LOCK = threading.Lock()


def limiter_for(host: str) -> RateLimiter:
    with _LIMITERS_LOCK:
        return _limiter_for(host)


def _limiter_for(host: str) -> RateLimiter:
    if host not in _LIMITERS:
        if host.endswith("nvd.nist.gov"):
            keyed = bool(os.environ.get("NVD_API_KEY"))
            _LIMITERS[host] = RateLimiter(40 if keyed else 4, 31.0)
        elif host.endswith("api.github.com"):
            _LIMITERS[host] = RateLimiter(60, 60.0)
        elif host.endswith("mitre.org"):
            _LIMITERS[host] = RateLimiter(4, 1.0)
        else:
            _LIMITERS[host] = RateLimiter(10, 1.0)
    return _LIMITERS[host]


def cache_dir() -> Path:
    d = Path(os.environ.get("FAULTLINE_CACHE", Path(__file__).resolve().parent.parent / "data" / "cache"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cache_path(url: str) -> Path:
    return cache_dir() / (hashlib.sha256(url.encode()).hexdigest()[:32] + ".json")


def get_json(
    url: str,
    headers: dict[str, str] | None = None,
    cache_ttl: float | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Any | None:
    """GET a JSON document.  Returns parsed JSON, or None after all retries fail.

    cache_ttl: seconds for which a cached copy is reused (None = no cache).
    A 404 is cached as {"__status__": 404} so it is not re-fetched within ttl.
    """
    cpath = _cache_path(url)
    if cache_ttl is not None and cpath.exists() and time.time() - cpath.stat().st_mtime < cache_ttl:
        try:
            data = json.loads(cpath.read_text(encoding="utf-8"))
            return None if isinstance(data, dict) and data.get("__status__") == 404 else data
        except (OSError, ValueError):
            pass

    host = urllib.parse.urlparse(url).netloc
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    delay = 2.0
    for attempt in range(1, MAX_ATTEMPTS + 1):
        limiter_for(host).wait()
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
            data = json.loads(raw.decode("utf-8"))
            if cache_ttl is not None:
                try:
                    cpath.write_text(json.dumps(data), encoding="utf-8")
                except OSError:
                    pass
            return data
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                if cache_ttl is not None:
                    cpath.write_text(json.dumps({"__status__": 404}), encoding="utf-8")
                return None
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            if exc.code in (403, 429, 500, 502, 503, 504) and attempt < MAX_ATTEMPTS:
                wait = max(float(retry_after) if retry_after and retry_after.isdigit() else 0.0, delay, 6.0 if exc.code == 429 else 0.0)
                log.warning("HTTP %s from %s (attempt %d/%d); retrying in %.0fs", exc.code, host, attempt, MAX_ATTEMPTS, wait)
                time.sleep(min(wait, 120))
                delay = min(delay * 2, 60)
                continue
            log.error("HTTP %s fetching %s", exc.code, url)
            return None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            if attempt < MAX_ATTEMPTS:
                log.warning("%s fetching %s (attempt %d/%d); retrying in %.0fs", exc.__class__.__name__, host, attempt, MAX_ATTEMPTS, delay)
                time.sleep(delay)
                delay = min(delay * 2, 60)
                continue
            log.error("giving up on %s: %s", url, exc)
            return None
    return None


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
