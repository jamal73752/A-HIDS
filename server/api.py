"""
api.py - Flask REST API for A-HIDS server.

Exposes endpoints for client data ingestion, alert retrieval, client
management, statistics, authentication, and report generation.
Token-based authentication is enforced on all data endpoints.
"""

import json
import logging
import os
import sys
from datetime import datetime
from functools import wraps
from typing import Any, Dict, Tuple

from flask import Flask, jsonify, request, Response

# Ensure project root is on sys.path when module is imported directly
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from server.ai_engine import AIEngine           # noqa: E402
from server.alert_manager import AlertManager   # noqa: E402
from server.database import DatabaseManager     # noqa: E402
from server.report_generator import ReportGenerator  # noqa: E402
from server.rule_engine import RuleEngine       # noqa: E402

logger = logging.getLogger(__name__)

# ── Flask application factory ─────────────────────────────────────────────────


def create_app(config: Dict[str, Any] | None = None) -> Flask:
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
    db_path = server_cfg.get("database", "ahids.db")
    db_manager = DatabaseManager(db_path)
    ai_engine = AIEngine(
        model_path=ai_cfg.get("model_path", "models/"),
        anomaly_threshold=float(ai_cfg.get("anomaly_threshold", 0.7)),
    )
    rule_engine = RuleEngine()
    alert_manager = AlertManager(db_manager, alerts_cfg)
    report_generator = ReportGenerator()

    # Store the valid auth token; clients must present it as a Bearer token
    valid_token: str = cfg.get("client", {}).get("auth_token", "your-secret-token")

    # ── Authentication decorator ───────────────────────────────────────────

    def require_auth(f):
        """Decorator that validates Bearer token authentication."""
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                if token == valid_token:
                    return f(*args, **kwargs)
            return jsonify({"error": "Unauthorised"}), 401
        return decorated

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
        Client authentication endpoint.

        Accepts JSON body with ``token`` key.  Returns success indicator.
        This endpoint is unauthenticated so clients can obtain session
        confirmation.

        Returns:
            200 with ``{"authenticated": true}`` on success.
            401 on invalid token.
        """
        body = request.get_json(silent=True) or {}
        token = body.get("token", "")
        if token == valid_token:
            return jsonify({"authenticated": True, "message": "Token valid"}), 200
        return jsonify({"authenticated": False, "error": "Invalid token"}), 401

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
                    f"AI: {threat_level} "
                    f"(conf={prediction.get('confidence', 0):.2f}), "
                    f"Rules: {len(rule_matches)} matched"
                ),
                data={
                    "prediction": prediction,
                    "rule_matches": [r["name"] for r in rule_matches],
                },
            )

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
        Retrieve stored alerts.

        Query parameters:
          - ``severity``: Filter by severity (LOW/MEDIUM/HIGH/CRITICAL).
          - ``limit``:    Max results (default 100).

        Returns:
            200 with ``{"alerts": [...]}``
        """
        severity = request.args.get("severity")
        limit = int(request.args.get("limit", 100))
        alerts = db_manager.get_alerts(severity=severity, limit=limit)
        return jsonify({"alerts": alerts, "count": len(alerts)}), 200

    # POST /api/alerts/<id>/acknowledge ───────────────────────────────────
    @app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
    @require_auth
    def acknowledge_alert(alert_id: int):
        """Mark an alert as acknowledged."""
        ok = db_manager.acknowledge_alert(alert_id)
        if ok:
            return jsonify({"status": "acknowledged", "alert_id": alert_id}), 200
        return jsonify({"error": "Alert not found"}), 404

    # GET /api/clients ────────────────────────────────────────────────────
    @app.route("/api/clients", methods=["GET"])
    @require_auth
    def get_clients():
        """
        List all registered client agents.

        Returns:
            200 with ``{"clients": [...]}``
        """
        clients = db_manager.get_clients()
        return jsonify({"clients": clients, "count": len(clients)}), 200

    # GET /api/stats ──────────────────────────────────────────────────────
    @app.route("/api/stats", methods=["GET"])
    @require_auth
    def get_stats():
        """
        Return aggregated statistics.

        Returns:
            200 with stats dict.
        """
        stats = db_manager.get_stats()
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

        Returns:
            200 with HTML content-type.
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
