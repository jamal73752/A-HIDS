"""
api.py - Flask REST API for A-HIDS server.

Exposes endpoints for client data ingestion, alert retrieval, client
management, statistics, authentication, and report generation.

Phase 1 additions:
  - JWT per-client token auth (POST /api/auth/register, /refresh, /revoke)
  - Legacy shared-token auth preserved for backward compatibility
  - Redis caching on GET endpoints
  - WebSocket event broadcasts on new data / alerts
  - Rate limiting via SecurityManager
  - Security headers on all responses
"""

import logging
import os
import sys
from datetime import datetime
from functools import wraps
from typing import Any, Dict, Optional

from flask import Flask, jsonify, request, Response

# Ensure project root is on sys.path when module is imported directly
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from server.ai_engine import AIEngine           # noqa: E402
from server.alert_manager import AlertManager   # noqa: E402
from server.database import DatabaseManager, create_database  # noqa: E402
from server.report_generator import ReportGenerator  # noqa: E402
from server.rule_engine import RuleEngine       # noqa: E402

logger = logging.getLogger(__name__)

# ── Flask application factory ─────────────────────────────────────────────────


def create_app(config: Optional[Dict[str, Any]] = None) -> Flask:
    """
    Create and configure the A-HIDS Flask application.

    Args:
        config: Optional dict merged into app.config.

    Returns:
        Configured Flask app instance.
    """
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.urandom(32).hex()

    cfg = config or {}
    server_cfg = cfg.get("server", {})
    alerts_cfg = cfg.get("alerts", {})
    ai_cfg = cfg.get("ai", {})

    # ── Initialise server components ───────────────────────────────────────
    db_manager = create_database(cfg)
    ai_engine = AIEngine(
        model_path=ai_cfg.get("model_path", "models/"),
        anomaly_threshold=float(ai_cfg.get("anomaly_threshold", 0.7)),
    )
    rule_engine = RuleEngine()
    alert_manager = AlertManager(db_manager, alerts_cfg)
    report_generator = ReportGenerator()

    # Legacy shared-token (backward-compat): clients present this as Bearer
    valid_token: str = cfg.get("client", {}).get("auth_token", "your-secret-token")
    master_key: str = server_cfg.get(
        "master_key", cfg.get("client", {}).get("auth_token", "your-secret-token")
    )
    secret_key: str = server_cfg.get("secret_key", "your-secret-key")

    # ── Optional components (graceful no-ops when libs missing) ────────────

    # JWT auth manager
    _auth_manager = None
    if server_cfg.get("jwt_enabled", True):
        try:
            from server.auth_manager import AuthManager
            _auth_manager = AuthManager(
                secret_key=secret_key,
                db_manager=db_manager,
                token_expiry_hours=int(server_cfg.get("token_expiry_hours", 24)),
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.info("JWT auth manager unavailable: %s", exc)

    # Redis cache
    _cache = None
    redis_cfg = server_cfg.get("redis", {})
    if redis_cfg.get("enabled", False):
        try:
            from server.cache_manager import CacheManager
            _cache = CacheManager(redis_cfg)
        except Exception as exc:  # pylint: disable=broad-except
            logger.info("Cache manager unavailable: %s", exc)

    # WebSocket manager
    _ws_manager = None
    if server_cfg.get("websocket_enabled", True):
        try:
            from server.websocket_manager import WebSocketManager, create_socketio
            _sio = create_socketio(app)
            _ws_manager = WebSocketManager(_sio)
        except Exception as exc:  # pylint: disable=broad-except
            logger.info("WebSocket manager unavailable: %s", exc)

    # Security manager (rate limiting + headers)
    _security = None
    try:
        from server.security import SecurityManager
        redis_url = (
            "redis://{}:{}/{}".format(
                redis_cfg.get("host", "localhost"),
                redis_cfg.get("port", 6379),
                redis_cfg.get("db", 0),
            )
            if redis_cfg.get("enabled", False)
            else None
        )
        _security = SecurityManager(app, redis_url=redis_url)
    except Exception as exc:  # pylint: disable=broad-except
        logger.info("Security manager unavailable: %s", exc)

    # ── Authentication helpers ─────────────────────────────────────────────

    def require_auth(f):
        """
        Decorator that accepts either a valid JWT *or* the legacy shared token.
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                # 1. Try JWT validation first
                if _auth_manager and _auth_manager.verify_token(token) is not None:
                    return f(*args, **kwargs)
                # 2. Fall back to legacy shared token
                if token == valid_token:
                    return f(*args, **kwargs)
            if _security:
                _security.log_auth_failure()
            return jsonify({"error": "Unauthorised"}), 401
        return decorated

    # ── Cache helpers ──────────────────────────────────────────────────────

    def _cache_get(key: str):
        if _cache:
            return _cache.get_cached(key)
        return None

    def _cache_set(key: str, data: Any, ttl: int = 60):
        if _cache:
            _cache.set_cached(key, data, ttl)

    def _cache_invalidate(pattern: str):
        if _cache:
            _cache.invalidate_pattern(pattern)

    # ── Helper ─────────────────────────────────────────────────────────────

    def _resolve_client(data: Dict[str, Any]) -> int:
        """Look up or create a client row and return its ID."""
        hostname = data.get("hostname", "unknown")
        sys_info = data.get("system_info", {})
        ip_address = data.get("ip_address") or sys_info.get("ip_address", "")
        os_info = str(
            (sys_info.get("os_info") or {}).get("system", "")
            + " "
            + (sys_info.get("os_info") or {}).get("release", "")
        ).strip()
        return db_manager.add_client(hostname, ip_address, os_info)

    # ── Routes ─────────────────────────────────────────────────────────────

    # POST /api/auth ──────────────────────────────────────────────────────
    @app.route("/api/auth", methods=["POST"])
    def auth():
        """
        Legacy shared-token authentication endpoint (backward-compatible).

        Accepts JSON body with ``token`` key.  Returns success indicator.
        """
        body = request.get_json(silent=True) or {}
        token = body.get("token", "")
        if token == valid_token:
            return jsonify({"authenticated": True, "message": "Token valid"}), 200
        return jsonify({"authenticated": False, "error": "Invalid token"}), 401

    # POST /api/auth/register ─────────────────────────────────────────────
    @app.route("/api/auth/register", methods=["POST"])
    def auth_register():
        """
        Register a new client and receive a unique JWT.

        Request body:
          - ``master_key``:  Server master key.
          - ``client_id``:   Unique client identifier.
          - ``hostname``:    Client hostname.

        Returns:
            200 with ``{"token": "<jwt>"}`` on success.
            401 on invalid master key.
            503 if JWT auth is not available.
        """
        if _auth_manager is None:
            return jsonify({"error": "JWT auth not available"}), 503

        body = request.get_json(silent=True) or {}
        if body.get("master_key") != master_key:
            if _security:
                _security.log_auth_failure("invalid master_key on register")
            return jsonify({"error": "Invalid master key"}), 401

        client_id = body.get("client_id", "")
        hostname = body.get("hostname", "unknown")
        if not client_id:
            return jsonify({"error": "client_id is required"}), 400

        token = _auth_manager.generate_token(client_id, hostname)
        if token is None:
            return jsonify({"error": "Token generation failed"}), 500

        return jsonify({"token": token, "client_id": client_id}), 200

    # POST /api/auth/refresh ──────────────────────────────────────────────
    @app.route("/api/auth/refresh", methods=["POST"])
    def auth_refresh():
        """
        Refresh an expiring JWT and receive a new one.

        Request body:
          - ``token``: Current JWT.

        Returns:
            200 with ``{"token": "<new_jwt>"}`` on success.
            401 on invalid / expired token.
        """
        if _auth_manager is None:
            return jsonify({"error": "JWT auth not available"}), 503

        body = request.get_json(silent=True) or {}
        old_token = body.get("token", "")
        new_token = _auth_manager.refresh_token(old_token)
        if new_token is None:
            return jsonify({"error": "Invalid or expired token"}), 401

        return jsonify({"token": new_token}), 200

    # POST /api/auth/revoke ───────────────────────────────────────────────
    @app.route("/api/auth/revoke", methods=["POST"])
    def auth_revoke():
        """
        Revoke a client's JWT token.

        Request body:
          - ``token``: JWT to revoke.

        Returns:
            200 on success.
            400 if token is missing.
        """
        if _auth_manager is None:
            return jsonify({"error": "JWT auth not available"}), 503

        body = request.get_json(silent=True) or {}
        token = body.get("token", "")
        if not token:
            return jsonify({"error": "token is required"}), 400

        reason = body.get("reason", "client_request")
        ok = _auth_manager.revoke_token(token, reason)
        return jsonify({"revoked": ok}), 200

    # POST /api/data ──────────────────────────────────────────────────────
    @app.route("/api/data", methods=["POST"])
    @require_auth
    def receive_data():
        """
        Receive a collected-data payload from a client agent.

        Pipeline:
          1. Parse and validate JSON body.
          2. Resolve (create/update) the client record.
          3. Run AI engine prediction.
          4. Evaluate detection rules.
          5. Create alerts for matched rules.
          6. Store a summary event.
          7. Invalidate relevant caches.
          8. Broadcast WebSocket events.

        Returns:
            202 Accepted with analysis summary.
        """
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "Invalid JSON body"}), 400

        try:
            client_id = _resolve_client(data)

            # AI analysis
            prediction = ai_engine.predict(data)

            # Rule evaluation
            rule_matches = rule_engine.evaluate(data)

            # Alert creation
            alert_ids = alert_manager.process_all_rules(
                client_id, rule_matches, data
            )

            # Store event summary
            threat_level = prediction.get("threat_level", "Normal")
            severity_map = {
                "Normal": "LOW",
                "Suspicious": "MEDIUM",
                "Malicious": "CRITICAL",
            }
            db_manager.add_event(
                client_id=client_id,
                event_type="data_collection",
                severity=severity_map.get(threat_level, "LOW"),
                description=(
                    "AI: {} (conf={:.2f}), Rules: {} matched".format(
                        threat_level,
                        prediction.get("confidence", 0),
                        len(rule_matches),
                    )
                ),
                data={
                    "prediction": prediction,
                    "rule_matches": [r["name"] for r in rule_matches],
                },
            )

            # Invalidate caches
            _cache_invalidate("ahids:stats")
            _cache_invalidate("ahids:alerts*")
            _cache_invalidate("ahids:clients")

            # WebSocket broadcasts
            if _ws_manager:
                if alert_ids:
                    recent_alerts = db_manager.get_alerts(limit=1)
                    if recent_alerts:
                        _ws_manager.emit_new_alert(recent_alerts[0])
                stats = db_manager.get_stats()
                _ws_manager.emit_stats_update(stats)

            return jsonify(
                {
                    "status": "accepted",
                    "client_id": client_id,
                    "prediction": prediction,
                    "rules_matched": len(rule_matches),
                    "alerts_created": len(alert_ids),
                }
            ), 202

        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Error processing /api/data: %s", exc, exc_info=True)
            return jsonify({"error": "Internal server error"}), 500

    # GET /api/alerts ─────────────────────────────────────────────────────
    @app.route("/api/alerts", methods=["GET"])
    @require_auth
    def get_alerts():
        """
        Retrieve stored alerts (cached 15 seconds).

        Query parameters:
          - ``severity``: Filter by severity (LOW/MEDIUM/HIGH/CRITICAL).
          - ``limit``:    Max results (default 100).
        """
        severity = request.args.get("severity")
        limit = int(request.args.get("limit", 100))
        cache_key = "ahids:alerts:{}:{}".format(severity, limit)

        cached = _cache_get(cache_key)
        if cached is not None:
            return jsonify(cached), 200

        alerts = db_manager.get_alerts(severity=severity, limit=limit)
        result = {"alerts": alerts, "count": len(alerts)}
        _cache_set(cache_key, result, ttl=15)
        return jsonify(result), 200

    # POST /api/alerts/<id>/acknowledge ───────────────────────────────────
    @app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
    @require_auth
    def acknowledge_alert(alert_id: int):
        """Mark an alert as acknowledged."""
        ok = db_manager.acknowledge_alert(alert_id)
        if ok:
            _cache_invalidate("ahids:alerts*")
            return jsonify({"status": "acknowledged", "alert_id": alert_id}), 200
        return jsonify({"error": "Alert not found"}), 404

    # GET /api/clients ────────────────────────────────────────────────────
    @app.route("/api/clients", methods=["GET"])
    @require_auth
    def get_clients():
        """
        List all registered client agents (cached 60 seconds).
        """
        cache_key = "ahids:clients"
        cached = _cache_get(cache_key)
        if cached is not None:
            return jsonify(cached), 200

        clients = db_manager.get_clients()
        result = {"clients": clients, "count": len(clients)}
        _cache_set(cache_key, result, ttl=60)
        return jsonify(result), 200

    # GET /api/stats ──────────────────────────────────────────────────────
    @app.route("/api/stats", methods=["GET"])
    @require_auth
    def get_stats():
        """
        Return aggregated statistics (cached 30 seconds).
        """
        cache_key = "ahids:stats"
        cached = _cache_get(cache_key)
        if cached is not None:
            return jsonify(cached), 200

        stats = db_manager.get_stats()
        _cache_set(cache_key, stats, ttl=30)
        return jsonify(stats), 200

    # GET /api/events ─────────────────────────────────────────────────────
    @app.route("/api/events", methods=["GET"])
    @require_auth
    def get_events():
        """Return recent events, optionally filtered by client or severity."""
        client_id = request.args.get("client_id", type=int)
        severity = request.args.get("severity")
        limit = int(request.args.get("limit", 200))
        events = db_manager.get_events(
            client_id=client_id, severity=severity, limit=limit
        )
        return jsonify({"events": events, "count": len(events)}), 200

    # GET /api/report ─────────────────────────────────────────────────────
    @app.route("/api/report", methods=["GET"])
    @require_auth
    def get_report():
        """
        Generate and return an HTML security report.
        """
        try:
            html = report_generator.generate_html_report(db_manager)
            return Response(html, mimetype="text/html"), 200
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Report generation failed: %s", exc)
            return jsonify({"error": "Report generation failed"}), 500

    # GET /health ─────────────────────────────────────────────────────────
    @app.route("/health", methods=["GET"])
    def health():
        """Simple health check endpoint (no authentication required)."""
        return jsonify(
            {
                "status": "ok",
                "timestamp": datetime.now().isoformat(),
                "service": "A-HIDS Server",
            }
        ), 200

    logger.info("A-HIDS API application created")
    return app
