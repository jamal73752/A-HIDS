"""
security.py - Rate limiting and security hardening for A-HIDS server.

Provides IP-based rate limiting, request validation, security headers,
and input sanitisation.  Uses flask-limiter when available; falls back
gracefully when it is not installed.
"""

import logging
import os
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set

from flask import Flask, Response, jsonify, request

logger = logging.getLogger(__name__)

# ── Default limits ─────────────────────────────────────────────────────────────

LIMIT_DATA_POST = "60 per minute"
LIMIT_AUTH_POST = "10 per minute"
LIMIT_GET_API = "120 per minute"

# Maximum accepted payload size in bytes (1 MB)
MAX_PAYLOAD_BYTES = 1 * 1024 * 1024


class SecurityManager:
    """
    Centralised security layer for the A-HIDS Flask application.

    Optionally integrates flask-limiter for rate limiting.  When
    flask-limiter is not installed all rate-limiting decorators are
    transparent no-ops so the API still functions normally.

    Args:
        app:            Configured Flask application instance.
        redis_url:      Redis URL for the rate-limiter storage backend.
                        Falls back to in-memory storage if not provided.
        ip_whitelist:   Set of IP addresses that bypass rate limits.
        ip_blacklist:   Set of IP addresses that are always denied.
    """

    def __init__(
        self,
        app: Flask,
        redis_url: Optional[str] = None,
        ip_whitelist: Optional[Set[str]] = None,
        ip_blacklist: Optional[Set[str]] = None,
    ):
        self._app = app
        self._ip_whitelist: Set[str] = ip_whitelist or set()
        self._ip_blacklist: Set[str] = ip_blacklist or set()
        self._limiter = None
        self._limiter_available = False

        self._init_limiter(redis_url)
        self._register_hooks()

    # ── Initialisation ─────────────────────────────────────────────────────────

    def _init_limiter(self, redis_url: Optional[str]) -> None:
        """Set up flask-limiter if installed."""
        try:
            from flask_limiter import Limiter
            from flask_limiter.util import get_remote_address

            storage_uri = redis_url or "memory://"
            self._limiter = Limiter(
                key_func=get_remote_address,
                app=self._app,
                storage_uri=storage_uri,
                default_limits=[LIMIT_GET_API],
            )
            self._limiter_available = True
            logger.info("Rate limiter initialised (storage=%s)", storage_uri)
        except ImportError:
            logger.info(
                "flask-limiter not installed – rate limiting disabled. "
                "Install it with: pip install flask-limiter"
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Rate limiter init failed: %s – continuing without.", exc)

    def _register_hooks(self) -> None:
        """Register before/after request hooks on the Flask app."""

        @self._app.before_request
        def _check_blacklist():
            """Block requests from blacklisted IPs."""
            ip = request.remote_addr
            if ip in self._ip_blacklist:
                logger.warning("Blocked request from blacklisted IP: %s", ip)
                return jsonify({"error": "Forbidden"}), 403
            return None

        @self._app.before_request
        def _check_payload_size():
            """Reject oversized request bodies."""
            content_length = request.content_length
            if content_length and content_length > MAX_PAYLOAD_BYTES:
                logger.warning(
                    "Payload too large from %s: %d bytes",
                    request.remote_addr,
                    content_length,
                )
                return jsonify({"error": "Payload too large (max 1 MB)"}), 413
            return None

        @self._app.after_request
        def _add_security_headers(response: Response) -> Response:
            """Attach standard security headers to every response."""
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; "
                "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; "
                "img-src 'self' data:; "
                "font-src 'self' cdnjs.cloudflare.com; "
                "connect-src 'self' ws: wss:;"
            )
            return response

    # ── Decorators ─────────────────────────────────────────────────────────────

    def limit(self, limit_string: str) -> Callable:
        """
        Apply *limit_string* rate limit to a route function.

        When flask-limiter is unavailable this returns a transparent
        pass-through decorator.

        Args:
            limit_string: Flask-Limiter limit string, e.g. ``"60/minute"``.

        Returns:
            Decorator.
        """
        if self._limiter_available and self._limiter is not None:
            return self._limiter.limit(limit_string)

        # No-op decorator
        def noop_decorator(f: Callable) -> Callable:
            return f
        return noop_decorator

    def validate_json_fields(self, required_fields: List[str]) -> Callable:
        """
        Decorator that validates required JSON fields in the request body.

        Returns 400 if any required field is missing.

        Args:
            required_fields: List of field names that must be present.

        Returns:
            Decorator.
        """
        def decorator(f: Callable) -> Callable:
            @wraps(f)
            def wrapper(*args, **kwargs):
                body = request.get_json(silent=True) or {}
                missing = [field for field in required_fields if field not in body]
                if missing:
                    return jsonify(
                        {"error": f"Missing required fields: {missing}"}
                    ), 400
                return f(*args, **kwargs)
            return wrapper
        return decorator

    # ── Public helpers ─────────────────────────────────────────────────────────

    def log_auth_failure(self, reason: str = "") -> None:
        """
        Log an authentication failure with contextual information.

        Args:
            reason: Human-readable failure description.
        """
        logger.warning(
            "AUTH FAILURE ip=%s path=%s reason=%s",
            request.remote_addr,
            request.path,
            reason or "invalid token",
        )

    def add_to_blacklist(self, ip: str) -> None:
        """Add *ip* to the runtime IP blacklist."""
        self._ip_blacklist.add(ip)
        logger.info("IP added to blacklist: %s", ip)

    def remove_from_blacklist(self, ip: str) -> None:
        """Remove *ip* from the runtime IP blacklist."""
        self._ip_blacklist.discard(ip)

    def add_to_whitelist(self, ip: str) -> None:
        """Add *ip* to the runtime IP whitelist (bypasses rate limits)."""
        self._ip_whitelist.add(ip)
