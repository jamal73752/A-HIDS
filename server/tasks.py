"""
tasks.py - Celery background task definitions for A-HIDS server.

Provides async tasks for AI analysis, email alerts, report generation,
model retraining, and data cleanup.  Falls back gracefully when Celery
or Redis is not available.
"""

import logging
import os
import sys
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Ensure project root is importable
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


def _create_celery_app(broker_url: str = "redis://localhost:6379/0"):
    """
    Create and return a Celery application instance.

    Returns None if Celery is not installed.

    Args:
        broker_url: Redis (or other) broker URL.

    Returns:
        Celery app or None.
    """
    try:
        from celery import Celery

        celery_app = Celery(
            "ahids_tasks",
            broker=broker_url,
            backend=broker_url,
            include=["server.tasks"],
        )

        celery_app.conf.update(
            task_serializer="json",
            accept_content=["json"],
            result_serializer="json",
            timezone="UTC",
            enable_utc=True,
            # Periodic task schedule
            beat_schedule={
                "retrain-model-daily": {
                    "task": "server.tasks.retrain_model_task",
                    "schedule": 86400,  # every 24 hours
                },
                "cleanup-old-data": {
                    "task": "server.tasks.cleanup_old_data_task",
                    "schedule": 43200,  # every 12 hours
                },
                "generate-daily-report": {
                    "task": "server.tasks.generate_report_task",
                    "schedule": 86400,  # every 24 hours
                },
            },
        )

        return celery_app
    except ImportError:
        logger.info(
            "Celery not installed – background tasks disabled. "
            "Install it with: pip install celery"
        )
        return None


# Module-level Celery app (lazily created; may be None)
_celery = None


def get_celery_app(broker_url: str = "redis://localhost:6379/0"):
    """Return the module-level Celery app, creating it on first call."""
    global _celery  # pylint: disable=global-statement
    if _celery is None:
        _celery = _create_celery_app(broker_url)
    return _celery


# ── Task definitions ───────────────────────────────────────────────────────────

def _make_task(name: str):
    """
    Decorator factory that registers a function as a Celery task if
    Celery is available, otherwise wraps it as a plain callable.
    """
    def decorator(func):
        app = get_celery_app()
        if app is not None:
            return app.task(name=name)(func)
        # No Celery → return function with a no-op .delay() method
        func.delay = lambda *a, **kw: None
        return func
    return decorator


@_make_task("server.tasks.analyze_data_task")
def analyze_data_task(data: Dict[str, Any], config: Optional[Dict] = None) -> Dict:
    """
    Run AI analysis on *data* payload in the background.

    Args:
        data:   Collected-data dict from the client.
        config: Optional AI config overrides.

    Returns:
        Analysis result dict.
    """
    try:
        from server.ai_engine import AIEngine
        from server.rule_engine import RuleEngine

        ai_cfg = (config or {}).get("ai", {})
        engine = AIEngine(
            model_path=ai_cfg.get("model_path", "models/"),
            anomaly_threshold=float(ai_cfg.get("anomaly_threshold", 0.7)),
        )
        rule_engine = RuleEngine()

        prediction = engine.predict(data)
        rule_matches = rule_engine.evaluate(data)

        return {
            "prediction": prediction,
            "rule_matches": [r["name"] for r in rule_matches],
        }
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("analyze_data_task failed: %s", exc)
        return {"error": str(exc)}


@_make_task("server.tasks.send_email_alert_task")
def send_email_alert_task(alert: Dict[str, Any], alerts_config: Optional[Dict] = None) -> bool:
    """
    Send an email notification for *alert* in the background.

    Args:
        alert:         Alert dict.
        alerts_config: Email configuration dict.

    Returns:
        True if the email was sent successfully, False otherwise.
    """
    try:
        from server.alert_manager import AlertManager
        from server.database import DatabaseManager

        db = DatabaseManager(":memory:")
        manager = AlertManager(db, alerts_config or {})
        manager._send_email_alert(alert)  # pylint: disable=protected-access
        return True
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("send_email_alert_task failed: %s", exc)
        return False


@_make_task("server.tasks.generate_report_task")
def generate_report_task(params: Optional[Dict] = None) -> str:
    """
    Generate an HTML security report in the background.

    Args:
        params: Optional parameters for the report generator.

    Returns:
        HTML report string or empty string on failure.
    """
    try:
        from server.database import DatabaseManager
        from server.report_generator import ReportGenerator

        db_path = (params or {}).get("db_path", "ahids.db")
        db = DatabaseManager(db_path)
        generator = ReportGenerator()
        return generator.generate_html_report(db)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("generate_report_task failed: %s", exc)
        return ""


@_make_task("server.tasks.retrain_model_task")
def retrain_model_task(config: Optional[Dict] = None) -> bool:
    """
    Retrain the AI model using the latest stored data.

    Args:
        config: Optional AI config dict.

    Returns:
        True if retraining succeeded, False otherwise.
    """
    try:
        from server.ai_engine import AIEngine

        ai_cfg = (config or {}).get("ai", {})
        model_path = ai_cfg.get("model_path", "models/")
        csv_path = os.path.join(model_path, "sample_data.csv")
        if not os.path.isfile(csv_path):
            logger.warning("No training data found at %s", csv_path)
            return False

        engine = AIEngine(model_path=model_path, anomaly_threshold=0.7)
        success = engine.train(csv_path=csv_path)
        if success:
            logger.info("Model retrained successfully")
        return success
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("retrain_model_task failed: %s", exc)
        return False


@_make_task("server.tasks.cleanup_old_data_task")
def cleanup_old_data_task(
    db_path: str = "ahids.db",
    retention_days: int = 90,
) -> int:
    """
    Delete events and alerts older than *retention_days* days.

    Args:
        db_path:        Path to the SQLite database file.
        retention_days: Data retention period in days.

    Returns:
        Number of records deleted.
    """
    try:
        import sqlite3
        from datetime import datetime, timedelta

        cutoff = (datetime.now() - timedelta(days=retention_days)).isoformat()
        deleted = 0

        with sqlite3.connect(db_path) as conn:
            cur = conn.execute(
                "DELETE FROM events WHERE timestamp < ?", (cutoff,)
            )
            deleted += cur.rowcount
            cur = conn.execute(
                "DELETE FROM alerts WHERE timestamp < ?", (cutoff,)
            )
            deleted += cur.rowcount
            conn.commit()

        logger.info("Cleanup deleted %d old records (cutoff=%s)", deleted, cutoff)
        return deleted
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("cleanup_old_data_task failed: %s", exc)
        return 0
