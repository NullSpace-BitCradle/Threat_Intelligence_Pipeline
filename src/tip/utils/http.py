"""
Shared HTTP helpers for reference-data downloads.

``get_with_retry`` retries transient upstream failures (429, 5xx, dropped
connections, timeouts) with capped exponential backoff and honors a numeric
Retry-After. It calls ``requests.get`` directly, so tests that stub
``requests.get`` keep intercepting every download.

``fetch_stix_bundle`` downloads the ATT&CK STIX bundle once per process. The
techniques, APT groups and campaigns steps all read the same file, and it is
about 40 MB from a host that throttles anonymous clients.
"""
import time
from typing import Any, Dict, Optional

import requests

from tip.utils.config import get_config
from tip.utils.error_handler import get_logger

config = get_config()
logger = get_logger('http')

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
MAX_ATTEMPTS = 3
BACKOFF_BASE = 2.0
MAX_WAIT = 60.0

DEFAULT_STIX_URL = (
    'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/'
    'enterprise-attack/enterprise-attack.json'
)

# Patched to a no-op by the test suite.
_sleep = time.sleep

_stix_cache: Dict[str, Dict[str, Any]] = {}


def download_timeout() -> Any:
    """Read timeout for reference-data downloads (not the NVD API timeout)."""
    return config.get('database.download_timeout', 120)


def _retry_after(response: requests.Response) -> Optional[float]:
    value = response.headers.get('Retry-After', '')
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


def get_with_retry(url: str, **kwargs: Any) -> requests.Response:
    """``requests.get`` with retries on 429, 5xx, connection errors and timeouts.

    Returns the final response, so callers keep their own raise_for_status().
    Raises the last connection error or timeout once attempts run out. Retry
    log lines name the URL and status only, never request headers.
    """
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            response = requests.get(url, **kwargs)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            if attempt == MAX_ATTEMPTS:
                raise
            wait = BACKOFF_BASE ** attempt
            logger.warning(f"GET {url} failed ({type(e).__name__}); retry {attempt}/{MAX_ATTEMPTS - 1} in {wait:.0f}s")
            _sleep(wait)
            continue

        if response.status_code not in RETRY_STATUSES or attempt == MAX_ATTEMPTS:
            return response
        hinted = _retry_after(response)
        wait = min(MAX_WAIT, hinted if hinted is not None else BACKOFF_BASE ** attempt)
        logger.warning(f"GET {url} returned {response.status_code}; retry {attempt}/{MAX_ATTEMPTS - 1} in {wait:.0f}s")
        _sleep(wait)
    raise AssertionError("unreachable")  # pragma: no cover


def fetch_stix_bundle(url: Optional[str] = None) -> Dict[str, Any]:
    """The ATT&CK STIX bundle, downloaded once per process and shared read-only.

    Only a successful download is cached; a failure raises and the next
    caller tries again.
    """
    url = url or config.get('database.groups.url', DEFAULT_STIX_URL)
    cached = _stix_cache.get(url)
    if cached is not None:
        logger.info("Reusing ATT&CK STIX bundle downloaded earlier this run")
        return cached
    response = get_with_retry(url, timeout=download_timeout())
    response.raise_for_status()
    bundle: Dict[str, Any] = response.json()
    _stix_cache[url] = bundle
    return bundle


def clear_stix_cache() -> None:
    _stix_cache.clear()
