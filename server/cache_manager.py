"""
cache_manager.py - Redis caching layer for A-HIDS server.

Provides a simple get/set/invalidate interface backed by Redis.
Gracefully falls back to a no-op if Redis is unavailable so the
server operates normally without caching.
"""

import functools
import json
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class CacheManager:
    """
    Redis-backed cache with graceful no-op fallback.

    If Redis is not available the instance operates in *disabled* mode:
    all reads return None and all writes are silently skipped.

    Args:
        redis_config: Dict with keys ``host``, ``port``, ``db``, and
                      optionally ``password``.  An empty dict uses Redis
                      defaults (localhost:6379/0).
    """

    def __init__(self, redis_config: Optional[dict] = None):
        self._redis = None
        self._enabled = False
        cfg = redis_config or {}

        try:
            import redis as redis_lib

            self._redis = redis_lib.Redis(
                host=cfg.get("host", "localhost"),
                port=int(cfg.get("port", 6379)),
                db=int(cfg.get("db", 0)),
                password=cfg.get("password") or None,
                socket_connect_timeout=2,
                socket_timeout=2,
                decode_responses=True,
            )
            # Verify the connection is alive
            self._redis.ping()
            self._enabled = True
            logger.info(
                "Redis cache connected: %s:%s db=%s",
                cfg.get("host", "localhost"),
                cfg.get("port", 6379),
                cfg.get("db", 0),
            )
        except ImportError:
            logger.info(
                "redis library not installed – caching disabled. "
                "Install it with: pip install redis"
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.info("Redis unavailable (%s) – caching disabled.", exc)

    # ── Public API ─────────────────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        """True if a live Redis connection was established."""
        return self._enabled

    def get_cached(self, key: str) -> Optional[Any]:
        """
        Return cached value for *key*, or None if absent / cache disabled.

        Args:
            key: Cache key string.

        Returns:
            Deserialised Python object or None.
        """
        if not self._enabled:
            return None
        try:
            raw = self._redis.get(key)
            if raw is None:
                return None
            return json.loads(raw)
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("Cache read error for key=%s: %s", key, exc)
            return None

    def set_cached(self, key: str, data: Any, ttl: int = 60) -> None:
        """
        Store *data* under *key* with a time-to-live of *ttl* seconds.

        Args:
            key:  Cache key string.
            data: JSON-serialisable object to cache.
            ttl:  Expiry in seconds (default 60).
        """
        if not self._enabled:
            return
        try:
            self._redis.setex(key, ttl, json.dumps(data, default=str))
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("Cache write error for key=%s: %s", key, exc)

    def invalidate(self, key: str) -> None:
        """
        Remove *key* from the cache.

        Args:
            key: Cache key to delete.
        """
        if not self._enabled:
            return
        try:
            self._redis.delete(key)
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("Cache invalidate error for key=%s: %s", key, exc)

    def invalidate_pattern(self, pattern: str) -> None:
        """
        Remove all keys matching *pattern* (glob-style, e.g. ``alerts:*``).

        Args:
            pattern: Glob pattern passed to Redis ``KEYS`` command.
        """
        if not self._enabled:
            return
        try:
            keys = self._redis.keys(pattern)
            if keys:
                self._redis.delete(*keys)
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("Cache invalidate_pattern error for pattern=%s: %s", pattern, exc)

    # ── Decorator ──────────────────────────────────────────────────────────────

    def cached(self, key: str, ttl: int = 60) -> Callable:
        """
        Decorator that caches the return value of a function.

        The cached value is stored under *key*.  If the cache is disabled
        or an error occurs the decorated function is called as normal.

        Args:
            key: Cache key for this function's result.
            ttl: Cache TTL in seconds.

        Returns:
            Decorator function.
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                cached_val = self.get_cached(key)
                if cached_val is not None:
                    logger.debug("Cache hit: %s", key)
                    return cached_val
                result = func(*args, **kwargs)
                self.set_cached(key, result, ttl)
                return result
            return wrapper
        return decorator
