"""
routes.py - Dashboard route handlers for A-HIDS.

All routes fetch live data from the A-HIDS REST API server and render
the appropriate Jinja2 templates.  A helper function wraps all server API
calls so failures are handled gracefully.
"""

import logging
from typing import Any, Dict

import requests
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint("dashboard", __name__)

# Request timeout for calls to the A-HIDS server API
_API_TIMEOUT = 5


# ── Helper ─────────────────────────────────────────────────────────────────────

def _api_get(path: str, params: Dict[str, Any] | None = None) -> Any:
    """
    Perform an authenticated GET against the A-HIDS server API.

    Args:
        path:   URL path, e.g. ``/api/alerts``.
        params: Optional query-string parameters.

    Returns:
        Parsed JSON response body, or an empty dict on any error.
    """
    base_url = current_app.config.get("SERVER_API_URL", "http://localhost:5000")
    token = current_app.config.get("AUTH_TOKEN", "your-secret-token")
    url = base_url.rstrip("/") + path

    try:
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            timeout=_API_TIMEOUT,
        )
        if resp.ok:
            return resp.json()
        logger.warning("API %s returned HTTP %d", path, resp.status_code)
    except requests.exceptions.RequestException as exc:
        logger.warning("API request to %s failed: %s", path, exc)

    return {}


def _api_post(path: str, json_body: Dict[str, Any] | None = None) -> Any:
    """
    Perform an authenticated POST against the A-HIDS server API.

    Args:
        path:      URL path.
        json_body: Request payload.

    Returns:
        Parsed JSON response body, or an empty dict on any error.
    """
    base_url = current_app.config.get("SERVER_API_URL", "http://localhost:5000")
    token = current_app.config.get("AUTH_TOKEN", "your-secret-token")
    url = base_url.rstrip("/") + path

    try:
        resp = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json=json_body or {},
            timeout=_API_TIMEOUT,
        )
        if resp.ok:
            return resp.json()
        logger.warning("API POST %s returned HTTP %d", path, resp.status_code)
    except requests.exceptions.RequestException as exc:
        logger.warning("API POST to %s failed: %s", path, exc)

    return {}


# ── Routes ─────────────────────────────────────────────────────────────────────

@dashboard_bp.route("/")
def index():
    """Main dashboard – stats cards and charts."""
    stats = _api_get("/api/stats")
    recent_alerts = _api_get("/api/alerts", params={"limit": 10})
    return render_template(
        "index.html",
        stats=stats,
        recent_alerts=recent_alerts.get("alerts", []),
        page="dashboard",
    )


@dashboard_bp.route("/alerts")
def alerts():
    """Alerts list with optional severity/client filter."""
    severity = request.args.get("severity", "")
    limit = request.args.get("limit", 100, type=int)

    params: Dict[str, Any] = {"limit": limit}
    if severity:
        params["severity"] = severity

    data = _api_get("/api/alerts", params=params)
    clients_data = _api_get("/api/clients")

    return render_template(
        "alerts.html",
        alerts=data.get("alerts", []),
        clients=clients_data.get("clients", []),
        current_severity=severity,
        page="alerts",
    )


@dashboard_bp.route("/alerts/<int:alert_id>/acknowledge", methods=["POST"])
def acknowledge_alert(alert_id: int):
    """Acknowledge a specific alert and redirect back to alerts list."""
    _api_post(f"/api/alerts/{alert_id}/acknowledge")
    flash(f"تم تأكيد التنبيه #{alert_id}", "success")
    return redirect(url_for("dashboard.alerts"))


@dashboard_bp.route("/clients")
def clients():
    """Connected client agents overview."""
    data = _api_get("/api/clients")
    return render_template(
        "clients.html",
        clients=data.get("clients", []),
        page="clients",
    )


@dashboard_bp.route("/logs")
def logs():
    """Recent security event log viewer."""
    data = _api_get("/api/events", params={"limit": 200})
    return render_template(
        "logs.html",
        events=data.get("events", []),
        page="logs",
    )


@dashboard_bp.route("/reports", methods=["GET", "POST"])
def reports():
    """Report generation and download."""
    report_html = None
    if request.method == "POST":
        # Proxy the report generation request to the server
        base_url = current_app.config.get("SERVER_API_URL", "http://localhost:5000")
        token = current_app.config.get("AUTH_TOKEN", "your-secret-token")
        try:
            resp = requests.get(
                f"{base_url}/api/report",
                headers={"Authorization": f"Bearer {token}"},
                timeout=15,
            )
            if resp.ok:
                report_html = resp.text
                flash("تم إنشاء التقرير بنجاح", "success")
            else:
                flash("فشل إنشاء التقرير", "danger")
        except requests.exceptions.RequestException as exc:
            logger.error("Report generation request failed: %s", exc)
            flash("خطأ في الاتصال بالخادم", "danger")

    return render_template(
        "reports.html",
        report_html=report_html,
        page="reports",
    )


@dashboard_bp.route("/settings", methods=["GET", "POST"])
def settings():
    """System settings viewer and editor."""
    cfg = current_app.config.get("AHIDS_CONFIG", {})
    saved = False

    if request.method == "POST":
        # Update in-memory config from form data
        form = request.form
        try:
            client_cfg = cfg.setdefault("client", {})
            client_cfg["server_url"] = form.get("server_url", "")
            client_cfg["auth_token"] = form.get("auth_token", "")
            client_cfg["collection_interval"] = int(
                form.get("collection_interval", 30)
            )

            alerts_cfg = cfg.setdefault("alerts", {})
            alerts_cfg["email_enabled"] = "email_enabled" in form
            alerts_cfg["smtp_server"] = form.get("smtp_server", "")
            alerts_cfg["smtp_port"] = int(form.get("smtp_port", 587))
            alerts_cfg["email_from"] = form.get("email_from", "")
            alerts_cfg["email_to"] = form.get("email_to", "")

            ai_cfg = cfg.setdefault("ai", {})
            ai_cfg["anomaly_threshold"] = float(
                form.get("anomaly_threshold", 0.7)
            )

            current_app.config["AHIDS_CONFIG"] = cfg
            saved = True
            flash("تم حفظ الإعدادات بنجاح", "success")
        except (ValueError, KeyError) as exc:
            logger.error("Settings save error: %s", exc)
            flash("خطأ في حفظ الإعدادات", "danger")

    return render_template(
        "settings.html",
        config=cfg,
        saved=saved,
        page="settings",
    )
