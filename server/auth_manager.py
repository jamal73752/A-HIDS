"""
auth_manager.py - JWT-based per-client token authentication for A-HIDS.

Generates, verifies, refreshes, and revokes JWT tokens for each client.
Tokens contain client_id, hostname, issued_at, and expires_at claims.
The token blacklist is stored in the database for persistence.
"""

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Default token expiration in hours
DEFAULT_TOKEN_EXPIRY_HOURS = 24


def _hash_token(token: str) -> str:
    """Return a SHA-256 hex digest of *token* for safe storage."""
    return hashlib.sha256(token.encode()).hexdigest()


class AuthManager:
    """
    Manages JWT authentication tokens for A-HIDS clients.

    Requires the ``PyJWT`` library (``pip install PyJWT``).

    Args:
        secret_key:         HMAC secret used to sign tokens.
        db_manager:         DatabaseManager instance (used for blacklist).
        token_expiry_hours: Lifetime of issued tokens in hours.
    """

    def __init__(
        self,
        secret_key: str,
        db_manager: Any,
        token_expiry_hours: int = DEFAULT_TOKEN_EXPIRY_HOURS,
    ):
        self._secret = secret_key
        self._db = db_manager
        self._expiry_hours = token_expiry_hours
        self._jwt_available = self._check_jwt()

    # ── Internal helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _check_jwt() -> bool:
        """Return True if PyJWT is importable."""
        try:
            import jwt  # noqa: F401
            return True
        except ImportError:
            logger.warning(
                "PyJWT not installed – JWT auth unavailable. "
                "Install it with: pip install PyJWT"
            )
            return False

    def _import_jwt(self):
        """Import and return the jwt module, raising ImportError if absent."""
        import jwt
        return jwt

    # ── Public API ─────────────────────────────────────────────────────────────

    def generate_token(self, client_id: str, hostname: str) -> Optional[str]:
        """
        Issue a new JWT for *client_id* / *hostname*.

        Args:
            client_id: Unique client identifier (string or int).
            hostname:  Client hostname embedded in the token payload.

        Returns:
            JWT string on success, None if PyJWT is unavailable.
        """
        if not self._jwt_available:
            return None

        jwt = self._import_jwt()
        now = datetime.now(tz=timezone.utc)
        payload = {
            "client_id": str(client_id),
            "hostname": hostname,
            "iat": now,
            "exp": now + timedelta(hours=self._expiry_hours),
        }
        try:
            token = jwt.encode(payload, self._secret, algorithm="HS256")
            # PyJWT ≥2.0 returns str; ≤1.x returns bytes
            if isinstance(token, bytes):
                token = token.decode()
            self._db.store_client_token(
                client_id=str(client_id),
                token_hash=_hash_token(token),
                expires_at=(now + timedelta(hours=self._expiry_hours)).isoformat(),
            )
            logger.debug("JWT issued for client_id=%s hostname=%s", client_id, hostname)
            return token
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Token generation failed: %s", exc)
            return None

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate *token* and return its decoded payload, or None.

        Checks:
          - Signature validity
          - Expiration (exp claim)
          - Token blacklist (revoked tokens)

        Args:
            token: JWT string from the ``Authorization: Bearer …`` header.

        Returns:
            Decoded payload dict, or None if invalid / expired / revoked.
        """
        if not self._jwt_available:
            return None

        jwt = self._import_jwt()
        try:
            payload = jwt.decode(token, self._secret, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            logger.debug("JWT expired")
            return None
        except jwt.InvalidTokenError as exc:
            logger.debug("JWT invalid: %s", exc)
            return None

        # Check blacklist
        if self._db.is_token_revoked(_hash_token(token)):
            logger.debug("JWT is revoked")
            return None

        return payload

    def refresh_token(self, old_token: str) -> Optional[str]:
        """
        Issue a fresh token if *old_token* is still valid.

        The old token is NOT revoked so that in-flight requests can
        complete.  The new token has a fresh expiry window.

        Args:
            old_token: Current (possibly near-expiry) JWT string.

        Returns:
            New JWT string, or None if the old token is invalid.
        """
        payload = self.verify_token(old_token)
        if payload is None:
            return None
        return self.generate_token(payload["client_id"], payload["hostname"])

    def revoke_token(self, token: str, reason: str = "revoked") -> bool:
        """
        Add *token* to the blacklist so it can no longer be used.

        Args:
            token:  JWT string to revoke.
            reason: Human-readable reason for audit purposes.

        Returns:
            True if the token was added to the blacklist.
        """
        try:
            self._db.revoke_token(_hash_token(token), reason)
            logger.info("Token revoked (reason=%s)", reason)
            return True
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Token revocation failed: %s", exc)
            return False
