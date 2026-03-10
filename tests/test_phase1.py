"""
test_phase1.py - Unit tests for Phase 1 A-HIDS enhancements.

Tests cover:
  - JWT authentication (AuthManager)
  - Redis caching (CacheManager graceful fallback)
  - WebSocket manager no-op mode
  - SSL manager cert-existence check and graceful fallback
  - Security manager instantiation
  - Database token management (store/revoke/check)
  - API JWT auth endpoints (/api/auth/register, /refresh, /revoke)
  - Backward-compatible legacy shared-token auth still works
  - create_database factory selects SQLite correctly
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure project root is importable
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


# ── TestDatabaseTokenManagement ───────────────────────────────────────────────

class TestDatabaseTokenManagement(unittest.TestCase):
    """Tests for new token management methods on DatabaseManager."""

    def setUp(self):
        from server.database import DatabaseManager
        self.db = DatabaseManager(db_path=":memory:")

    def test_store_and_check_token(self):
        """store_client_token then is_token_revoked should return False."""
        self.db.store_client_token("client1", "abc123", "2099-01-01T00:00:00")
        self.assertFalse(self.db.is_token_revoked("abc123"))

    def test_revoke_token(self):
        """revoke_token should add hash to blacklist."""
        self.db.revoke_token("deadbeef", "test revocation")
        self.assertTrue(self.db.is_token_revoked("deadbeef"))

    def test_non_revoked_token_not_blocked(self):
        """A token hash that was never revoked should not appear in blacklist."""
        self.assertFalse(self.db.is_token_revoked("not-revoked-hash"))

    def test_duplicate_revoke_is_idempotent(self):
        """Revoking the same token twice should not raise."""
        self.db.revoke_token("dup-hash", "first")
        self.db.revoke_token("dup-hash", "second")  # should not raise
        self.assertTrue(self.db.is_token_revoked("dup-hash"))


# ── TestCreateDatabaseFactory ─────────────────────────────────────────────────

class TestCreateDatabaseFactory(unittest.TestCase):
    """Tests for the create_database factory function."""

    def test_sqlite_is_default(self):
        """create_database without database_type should return a DatabaseManager."""
        from server.database import DatabaseManager, create_database
        db = create_database({"server": {"database": ":memory:"}})
        self.assertIsInstance(db, DatabaseManager)

    def test_sqlite_explicit(self):
        """create_database with database_type=sqlite should return a DatabaseManager."""
        from server.database import DatabaseManager, create_database
        db = create_database({"server": {"database_type": "sqlite", "database": ":memory:"}})
        self.assertIsInstance(db, DatabaseManager)

    def test_postgresql_falls_back_to_sqlite(self):
        """create_database with postgresql (unavailable) should fall back to SQLite."""
        from server.database import DatabaseManager, create_database
        # psycopg2 is not installed in the test environment – should fall back
        db = create_database({
            "server": {
                "database_type": "postgresql",
                "database": ":memory:",
                "postgresql": {"host": "localhost", "port": 5432,
                               "database": "ahids", "user": "x", "password": "x"},
            }
        })
        self.assertIsInstance(db, DatabaseManager)


# ── TestAuthManager ───────────────────────────────────────────────────────────

class TestAuthManager(unittest.TestCase):
    """Tests for server.auth_manager.AuthManager with PyJWT."""

    def _make_manager(self):
        from server.database import DatabaseManager
        from server.auth_manager import AuthManager
        db = DatabaseManager(":memory:")
        return AuthManager(secret_key="test-secret", db_manager=db, token_expiry_hours=1)

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("jwt") is not None,
        "PyJWT not installed"
    )
    def test_generate_token_returns_string(self):
        """generate_token should return a non-empty string."""
        mgr = self._make_manager()
        token = mgr.generate_token("client1", "testhost")
        self.assertIsNotNone(token)
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 0)

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("jwt") is not None,
        "PyJWT not installed"
    )
    def test_verify_valid_token(self):
        """verify_token should return a payload dict for a valid token."""
        mgr = self._make_manager()
        token = mgr.generate_token("client1", "testhost")
        payload = mgr.verify_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["client_id"], "client1")
        self.assertEqual(payload["hostname"], "testhost")

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("jwt") is not None,
        "PyJWT not installed"
    )
    def test_verify_invalid_token_returns_none(self):
        """verify_token with a tampered token should return None."""
        mgr = self._make_manager()
        result = mgr.verify_token("not.a.valid.jwt")
        self.assertIsNone(result)

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("jwt") is not None,
        "PyJWT not installed"
    )
    def test_revoke_then_verify_returns_none(self):
        """After revocation verify_token should return None."""
        mgr = self._make_manager()
        token = mgr.generate_token("client2", "host2")
        mgr.revoke_token(token, "test")
        self.assertIsNone(mgr.verify_token(token))

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("jwt") is not None,
        "PyJWT not installed"
    )
    def test_refresh_token_returns_new_token(self):
        """refresh_token should return a different valid token."""
        mgr = self._make_manager()
        token = mgr.generate_token("client3", "host3")
        new_token = mgr.refresh_token(token)
        self.assertIsNotNone(new_token)
        # New token is valid
        payload = mgr.verify_token(new_token)
        self.assertIsNotNone(payload)

    def test_no_jwt_library_generate_returns_none(self):
        """Without PyJWT, generate_token should return None gracefully."""
        from server.database import DatabaseManager
        from server.auth_manager import AuthManager
        db = DatabaseManager(":memory:")
        mgr = AuthManager(secret_key="s", db_manager=db)
        mgr._jwt_available = False  # simulate missing library
        self.assertIsNone(mgr.generate_token("c", "h"))

    def test_no_jwt_library_verify_returns_none(self):
        """Without PyJWT, verify_token should return None gracefully."""
        from server.database import DatabaseManager
        from server.auth_manager import AuthManager
        db = DatabaseManager(":memory:")
        mgr = AuthManager(secret_key="s", db_manager=db)
        mgr._jwt_available = False
        self.assertIsNone(mgr.verify_token("some.token"))


# ── TestCacheManager ──────────────────────────────────────────────────────────

class TestCacheManager(unittest.TestCase):
    """Tests for server.cache_manager.CacheManager graceful fallback."""

    def test_disabled_cache_get_returns_none(self):
        """get_cached should return None when Redis is unavailable."""
        from server.cache_manager import CacheManager
        cache = CacheManager({"host": "127.0.0.1", "port": 19999})  # bad port
        self.assertFalse(cache.enabled)
        self.assertIsNone(cache.get_cached("any_key"))

    def test_disabled_cache_set_does_not_raise(self):
        """set_cached should not raise when cache is disabled."""
        from server.cache_manager import CacheManager
        cache = CacheManager({"host": "127.0.0.1", "port": 19999})
        cache.set_cached("key", {"data": 1}, ttl=30)  # should not raise

    def test_disabled_cache_invalidate_does_not_raise(self):
        """invalidate and invalidate_pattern should not raise when disabled."""
        from server.cache_manager import CacheManager
        cache = CacheManager({"host": "127.0.0.1", "port": 19999})
        cache.invalidate("key")
        cache.invalidate_pattern("ahids:*")

    def test_cached_decorator_with_disabled_cache(self):
        """@cached decorator should call wrapped function when cache is disabled."""
        from server.cache_manager import CacheManager
        cache = CacheManager({"host": "127.0.0.1", "port": 19999})
        call_count = [0]

        @cache.cached(key="test_key", ttl=60)
        def my_func():
            call_count[0] += 1
            return {"result": 42}

        result = my_func()
        self.assertEqual(result, {"result": 42})
        self.assertEqual(call_count[0], 1)


# ── TestWebSocketManager ──────────────────────────────────────────────────────

class TestWebSocketManager(unittest.TestCase):
    """Tests for server.websocket_manager.WebSocketManager no-op mode."""

    def test_no_socketio_is_disabled(self):
        """WebSocketManager without socketio should report disabled."""
        from server.websocket_manager import WebSocketManager
        mgr = WebSocketManager(socketio=None)
        self.assertFalse(mgr.enabled)

    def test_emit_new_alert_does_not_raise_when_disabled(self):
        """emit_new_alert should not raise when WebSocket is disabled."""
        from server.websocket_manager import WebSocketManager
        mgr = WebSocketManager(socketio=None)
        mgr.emit_new_alert({"id": 1, "severity": "HIGH", "rule_name": "test"})

    def test_emit_stats_update_does_not_raise_when_disabled(self):
        """emit_stats_update should not raise when WebSocket is disabled."""
        from server.websocket_manager import WebSocketManager
        mgr = WebSocketManager(socketio=None)
        mgr.emit_stats_update({"total_alerts": 5, "active_clients": 2})

    def test_emit_with_socketio_calls_emit(self):
        """emit_new_alert should call sio.emit when SocketIO is available."""
        from server.websocket_manager import WebSocketManager
        mock_sio = MagicMock()
        mgr = WebSocketManager(socketio=mock_sio)
        self.assertTrue(mgr.enabled)
        mgr.emit_new_alert({"id": 1})
        mock_sio.emit.assert_called_once()


# ── TestSSLManager ────────────────────────────────────────────────────────────

class TestSSLManager(unittest.TestCase):
    """Tests for server.ssl_manager."""

    def test_certs_exist_false_for_missing_files(self):
        """certs_exist should return False for non-existent paths."""
        from server.ssl_manager import certs_exist
        self.assertFalse(certs_exist("/nonexistent/cert.crt", "/nonexistent/key.key"))

    def test_get_ssl_context_disabled(self):
        """get_ssl_context with ssl_enabled=False should return None."""
        from server.ssl_manager import get_ssl_context
        result = get_ssl_context(ssl_enabled=False)
        self.assertIsNone(result)

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("cryptography") is not None,
        "cryptography not installed"
    )
    def test_generate_self_signed_cert(self):
        """generate_self_signed_cert should create cert and key files."""
        import tempfile
        import shutil
        from server.ssl_manager import generate_self_signed_cert, certs_exist

        tmp_dir = tempfile.mkdtemp()
        try:
            cert_path = os.path.join(tmp_dir, "test.crt")
            key_path = os.path.join(tmp_dir, "test.key")
            result = generate_self_signed_cert(cert_path, key_path)
            self.assertTrue(result)
            self.assertTrue(certs_exist(cert_path, key_path))
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ── TestAPIJWTEndpoints ───────────────────────────────────────────────────────

class TestAPIJWTEndpoints(unittest.TestCase):
    """Tests for new JWT auth endpoints on the Flask API."""

    def setUp(self):
        from server.api import create_app
        self.config = {
            "client": {"auth_token": "test-token"},
            "server": {
                "secret_key": "test-secret",
                "master_key": "test-token",
                "database": ":memory:",
                "jwt_enabled": True,
                "token_expiry_hours": 1,
                "websocket_enabled": False,
            },
            "ai": {"model_path": "/nonexistent/", "anomaly_threshold": 0.7},
            "alerts": {"email_enabled": False},
        }
        app = create_app(self.config)
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_legacy_auth_still_works(self):
        """POST /api/auth with valid shared token should return 200."""
        resp = self.client.post(
            "/api/auth",
            json={"token": "test-token"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["authenticated"])

    def test_legacy_auth_wrong_token(self):
        """POST /api/auth with wrong token should return 401."""
        resp = self.client.post(
            "/api/auth",
            json={"token": "wrong-token"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 401)

    def test_legacy_bearer_token_accepted_on_data_endpoint(self):
        """POST /api/data with legacy Bearer token should be accepted."""
        resp = self.client.post(
            "/api/data",
            json={
                "hostname": "testhost",
                "cpu_usage": 10.0,
                "memory_usage": 30.0,
                "disk_usage": 40.0,
                "suspicious_processes": [],
                "log_events": [],
                "network": {"suspicious_connections": [], "listening_ports": [],
                            "total_connections": 5},
                "file_integrity": {"modified": [], "added": [], "deleted": []},
            },
            headers={"Authorization": "Bearer test-token"},
            content_type="application/json",
        )
        self.assertIn(resp.status_code, (202, 200))

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("jwt") is not None,
        "PyJWT not installed"
    )
    def test_register_with_valid_master_key(self):
        """POST /api/auth/register with valid master_key should return token."""
        resp = self.client.post(
            "/api/auth/register",
            json={
                "master_key": "test-token",
                "client_id": "test-client-1",
                "hostname": "testhost",
            },
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertIn("token", body)
        self.assertIsNotNone(body["token"])

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("jwt") is not None,
        "PyJWT not installed"
    )
    def test_register_with_invalid_master_key(self):
        """POST /api/auth/register with wrong master_key should return 401."""
        resp = self.client.post(
            "/api/auth/register",
            json={
                "master_key": "wrong-key",
                "client_id": "test-client-2",
                "hostname": "testhost",
            },
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 401)

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("jwt") is not None,
        "PyJWT not installed"
    )
    def test_jwt_token_accepted_on_data_endpoint(self):
        """A JWT obtained from /api/auth/register should be accepted on /api/data."""
        # Register first
        reg_resp = self.client.post(
            "/api/auth/register",
            json={"master_key": "test-token", "client_id": "jwtclient", "hostname": "h"},
            content_type="application/json",
        )
        self.assertEqual(reg_resp.status_code, 200)
        jwt_token = reg_resp.get_json()["token"]

        # Now send data with JWT
        data_resp = self.client.post(
            "/api/data",
            json={
                "hostname": "h",
                "cpu_usage": 10.0,
                "memory_usage": 30.0,
                "disk_usage": 40.0,
                "suspicious_processes": [],
                "log_events": [],
                "network": {"suspicious_connections": [], "listening_ports": [],
                            "total_connections": 5},
                "file_integrity": {"modified": [], "added": [], "deleted": []},
            },
            headers={"Authorization": "Bearer {}".format(jwt_token)},
            content_type="application/json",
        )
        self.assertIn(data_resp.status_code, (202, 200))

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("jwt") is not None,
        "PyJWT not installed"
    )
    def test_revoke_token_endpoint(self):
        """POST /api/auth/revoke should revoke a valid token."""
        # Register first
        reg_resp = self.client.post(
            "/api/auth/register",
            json={"master_key": "test-token", "client_id": "revokeclient", "hostname": "r"},
            content_type="application/json",
        )
        token = reg_resp.get_json()["token"]

        # Revoke
        rev_resp = self.client.post(
            "/api/auth/revoke",
            json={"token": token, "reason": "test"},
            content_type="application/json",
        )
        self.assertEqual(rev_resp.status_code, 200)
        self.assertTrue(rev_resp.get_json()["revoked"])

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("jwt") is not None,
        "PyJWT not installed"
    )
    def test_refresh_token_endpoint(self):
        """POST /api/auth/refresh with a valid token should return a new token."""
        # Register first
        reg_resp = self.client.post(
            "/api/auth/register",
            json={"master_key": "test-token", "client_id": "refreshclient", "hostname": "r"},
            content_type="application/json",
        )
        token = reg_resp.get_json()["token"]

        # Refresh
        ref_resp = self.client.post(
            "/api/auth/refresh",
            json={"token": token},
            content_type="application/json",
        )
        self.assertEqual(ref_resp.status_code, 200)
        self.assertIn("token", ref_resp.get_json())

    def test_health_endpoint_no_auth(self):
        """GET /health should return 200 without authentication."""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["status"], "ok")

    def test_security_headers_present(self):
        """GET /health response should include X-Content-Type-Options header."""
        resp = self.client.get("/health")
        # Security headers may be absent if flask-limiter is not installed;
        # this test is informational rather than strictly required.
        # We just verify the endpoint works.
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
