"""
sender.py - HTTP sender module for A-HIDS client.

Sends the collected system data to the A-HIDS server via a JSON POST
request.  Implements a retry mechanism with exponential backoff to
handle transient network failures gracefully.
"""

import logging
import time
from typing import Any, Dict

import requests

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

# Number of transmission attempts before giving up
MAX_RETRIES = 3

# Base back-off delay in seconds; doubles on each retry (1 → 2 → 4 s)
BACKOFF_BASE = 1

# Request timeout in seconds
REQUEST_TIMEOUT = 10


class Sender:
    """
    Transmits collected data payloads to the A-HIDS server.

    Handles authentication via a bearer token and retries failed
    requests with exponential back-off.

    Args:
        config: The ``client`` section of config.yaml as a dict,
                expected to contain ``server_url`` and ``auth_token``.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialise the sender from configuration.

        Args:
            config: Client configuration dict.
        """
        self._server_url: str = config.get(
            "server_url", "http://localhost:5000"
        ).rstrip("/")
        self._auth_token: str = config.get("auth_token", "")
        self._endpoint: str = f"{self._server_url}/api/data"
        self._headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._auth_token}",
        }
        logger.debug("Sender initialised – endpoint: %s", self._endpoint)

    # ── Public API ─────────────────────────────────────────────────────────────

    def send(self, payload: Dict[str, Any]) -> bool:
        """
        Send a data payload to the server with retries.

        Retries up to MAX_RETRIES times using exponential back-off
        (1 s, 2 s, 4 s) on connection errors or non-2xx responses.

        Args:
            payload: Collected data dict from DataCollector.collect().

        Returns:
            True if the payload was accepted by the server (HTTP 2xx),
            False if all retries were exhausted.
        """
        delay = BACKOFF_BASE

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                logger.debug(
                    "Sending payload to %s (attempt %d/%d)",
                    self._endpoint,
                    attempt,
                    MAX_RETRIES,
                )

                response = requests.post(
                    self._endpoint,
                    json=payload,
                    headers=self._headers,
                    timeout=REQUEST_TIMEOUT,
                )

                if response.ok:
                    logger.info(
                        "Payload delivered successfully (HTTP %d)",
                        response.status_code,
                    )
                    return True

                logger.warning(
                    "Server returned HTTP %d on attempt %d: %s",
                    response.status_code,
                    attempt,
                    response.text[:200],
                )

                # Do not retry on client errors (4xx) except 429 (rate limit)
                if 400 <= response.status_code < 500 and response.status_code != 429:
                    logger.error(
                        "Non-retryable HTTP error %d – aborting",
                        response.status_code,
                    )
                    return False

            except requests.exceptions.ConnectionError as exc:
                logger.warning(
                    "Connection error on attempt %d: %s", attempt, exc
                )
            except requests.exceptions.Timeout:
                logger.warning(
                    "Request timed out on attempt %d (timeout=%ds)",
                    attempt,
                    REQUEST_TIMEOUT,
                )
            except requests.exceptions.RequestException as exc:
                logger.error(
                    "Unexpected request exception on attempt %d: %s",
                    attempt,
                    exc,
                )

            # Exponential back-off before next attempt
            if attempt < MAX_RETRIES:
                logger.debug("Waiting %ds before retry…", delay)
                time.sleep(delay)
                delay *= 2

        logger.error(
            "Failed to deliver payload after %d attempts", MAX_RETRIES
        )
        return False

    def ping(self) -> bool:
        """
        Check whether the server is reachable.

        Returns:
            True if the server responds to a GET on ``/api/stats``.
        """
        try:
            resp = requests.get(
                f"{self._server_url}/api/stats",
                headers=self._headers,
                timeout=REQUEST_TIMEOUT,
            )
            return resp.ok
        except requests.exceptions.RequestException as exc:
            logger.debug("Ping failed: %s", exc)
            return False
