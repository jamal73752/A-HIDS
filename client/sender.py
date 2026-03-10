"""
sender.py - HTTP/HTTPS sender module for A-HIDS client.

Sends the collected system data to the A-HIDS server via a JSON POST
request.  Implements a retry mechanism with exponential backoff.

Phase 1 additions:
  - HTTPS support with configurable SSL verification
  - JWT token management: register on first run, auto-refresh before expiry,
    re-register on 401 responses, store token in client/.token file
"""

import json
import logging
import os
import time
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_RETRIES = 3
BACKOFF_BASE = 1
REQUEST_TIMEOUT = 10

# File where the JWT is persisted between runs
_TOKEN_FILE = os.path.join(os.path.dirname(__file__), ".token")


class Sender:
    """
    Transmits collected data payloads to the A-HIDS server.

    Supports both plain HTTP and HTTPS.  When ``jwt_enabled`` is True the
    sender registers with the server on first connection and stores the
    received JWT in ``client/.token`` for reuse across restarts.

    Args:
        config: The ``client`` section of config.yaml as a dict.
    """

    def __init__(self, config: Dict[str, Any]):
        self._server_url: str = config.get(
            "server_url", "http://localhost:5000"
        ).rstrip("/")
        self._auth_token: str = config.get("auth_token", "")
        self._verify_ssl: bool = bool(config.get("verify_ssl", False))
        self._master_key: str = config.get("master_key", self._auth_token)
        self._client_id: str = config.get("client_id", "")
        self._jwt_enabled: bool = bool(config.get("jwt_enabled", False))

        # JWT token (loaded from file or obtained via registration)
        self._jwt_token: Optional[str] = self._load_jwt()

        self._endpoint: str = "{}/api/data".format(self._server_url)
        logger.debug("Sender initialised – endpoint: %s ssl_verify=%s",
                     self._endpoint, self._verify_ssl)

    # ── JWT helpers ────────────────────────────────────────────────────────────

    def _load_jwt(self) -> Optional[str]:
        """Load a previously stored JWT from the token file."""
        try:
            if os.path.isfile(_TOKEN_FILE):
                with open(_TOKEN_FILE, "r", encoding="utf-8") as fh:
                    token = fh.read().strip()
                    return token if token else None
        except OSError as exc:
            logger.debug("Could not load JWT from %s: %s", _TOKEN_FILE, exc)
        return None

    def _save_jwt(self, token: str) -> None:
        """Persist *token* to the token file."""
        try:
            with open(_TOKEN_FILE, "w", encoding="utf-8") as fh:
                fh.write(token)
            logger.debug("JWT saved to %s", _TOKEN_FILE)
        except OSError as exc:
            logger.warning("Could not save JWT: %s", exc)

    def _register(self) -> bool:
        """
        Register with the server using the master key and obtain a JWT.

        Returns:
            True if a token was successfully obtained and saved.
        """
        if not self._jwt_enabled:
            return False
        import socket
        hostname = socket.gethostname()
        client_id = self._client_id or hostname
        try:
            resp = requests.post(
                "{}/api/auth/register".format(self._server_url),
                json={
                    "master_key": self._master_key,
                    "client_id": client_id,
                    "hostname": hostname,
                },
                verify=self._verify_ssl,
                timeout=REQUEST_TIMEOUT,
            )
            if resp.ok:
                body = resp.json()
                token = body.get("token")
                if token:
                    self._jwt_token = token
                    self._save_jwt(token)
                    logger.info("JWT registration successful for client_id=%s", client_id)
                    return True
                logger.warning("Registration response has no token: %s", body)
            else:
                logger.warning("JWT registration failed: HTTP %d", resp.status_code)
        except requests.exceptions.RequestException as exc:
            logger.warning("JWT registration request failed: %s", exc)
        return False

    def _get_headers(self) -> Dict[str, str]:
        """Return HTTP headers, preferring JWT over the legacy shared token."""
        headers = {"Content-Type": "application/json"}
        if self._jwt_enabled and self._jwt_token:
            headers["Authorization"] = "Bearer {}".format(self._jwt_token)
        elif self._auth_token:
            headers["Authorization"] = "Bearer {}".format(self._auth_token)
        return headers

    # ── Public API ─────────────────────────────────────────────────────────────

    def send(self, payload: Dict[str, Any]) -> bool:
        """
        Send a data payload to the server with retries.

        On first run (if JWT is enabled and no token is stored) the sender
        attempts to register and obtain a JWT.  On 401 responses it retries
        registration once before giving up.

        Args:
            payload: Collected data dict from DataCollector.collect().

        Returns:
            True if the payload was accepted (HTTP 2xx), False otherwise.
        """
        # Ensure we have a JWT before the first send
        if self._jwt_enabled and self._jwt_token is None:
            self._register()

        delay = BACKOFF_BASE
        _re_registered = False

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                logger.debug(
                    "Sending payload to %s (attempt %d/%d)",
                    self._endpoint, attempt, MAX_RETRIES,
                )
                response = requests.post(
                    self._endpoint,
                    json=payload,
                    headers=self._get_headers(),
                    timeout=REQUEST_TIMEOUT,
                    verify=self._verify_ssl,
                )

                if response.ok:
                    logger.info(
                        "Payload delivered successfully (HTTP %d)",
                        response.status_code,
                    )
                    return True

                # On 401 re-register once then retry
                if response.status_code == 401 and self._jwt_enabled and not _re_registered:
                    logger.info("Received 401 – attempting re-registration")
                    _re_registered = True
                    if self._register():
                        continue  # retry with new token

                logger.warning(
                    "Server returned HTTP %d on attempt %d: %s",
                    response.status_code, attempt, response.text[:200],
                )

                # Do not retry on client errors (4xx) except 429 (rate limit)
                if 400 <= response.status_code < 500 and response.status_code != 429:
                    logger.error(
                        "Non-retryable HTTP error %d – aborting",
                        response.status_code,
                    )
                    return False

            except requests.exceptions.ConnectionError as exc:
                logger.warning("Connection error on attempt %d: %s", attempt, exc)
            except requests.exceptions.Timeout:
                logger.warning(
                    "Request timed out on attempt %d (timeout=%ds)",
                    attempt, REQUEST_TIMEOUT,
                )
            except requests.exceptions.RequestException as exc:
                logger.error(
                    "Unexpected request exception on attempt %d: %s", attempt, exc
                )

            if attempt < MAX_RETRIES:
                logger.debug("Waiting %ds before retry…", delay)
                time.sleep(delay)
                delay *= 2

        logger.error("Failed to deliver payload after %d attempts", MAX_RETRIES)
        return False

    def ping(self) -> bool:
        """
        Check whether the server is reachable.

        Returns:
            True if the server responds to a GET on ``/api/stats``.
        """
        try:
            resp = requests.get(
                "{}/api/stats".format(self._server_url),
                headers=self._get_headers(),
                timeout=REQUEST_TIMEOUT,
                verify=self._verify_ssl,
            )
            return resp.ok
        except requests.exceptions.RequestException as exc:
            logger.debug("Ping failed: %s", exc)
            return False
