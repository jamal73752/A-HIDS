"""
alert_manager.py - Alert creation and notification for A-HIDS server.

Manages alert lifecycle: creation with deduplication, email notification,
file logging, and database persistence.
"""

import logging
import smtplib
import socket
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

from server.db.database import DatabaseManager

logger = logging.getLogger(__name__)

# ── Severity constants ─────────────────────────────────────────────────────────

LOW = 1
MEDIUM = 2
HIGH = 3
CRITICAL = 4

SEVERITY_MAP = {
    "LOW": LOW,
    "MEDIUM": MEDIUM,
    "HIGH": HIGH,
    "CRITICAL": CRITICAL,
}

# Alert deduplication window in seconds (5 minutes)
DEDUP_WINDOW_SECONDS = 300

# Separate file logger for persistent alert history
_alert_file_logger = logging.getLogger("ahids.alerts")
_alert_file_handler = logging.FileHandler("alerts.log", encoding="utf-8")
_alert_file_handler.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
)
_alert_file_logger.addHandler(_alert_file_handler)
_alert_file_logger.setLevel(logging.DEBUG)
_alert_file_logger.propagate = False


class AlertManager:
    """
    Centralised alert handling for the A-HIDS server.

    Responsibilities:
      - Create alerts in the database (with deduplication)
      - Write alerts to alerts.log
      - Send email notifications when configured

    Args:
        db_manager:    Initialised DatabaseManager instance.
        alerts_config: The ``alerts`` section of config.yaml as a dict.
    """

    def __init__(
        self,
        db_manager: DatabaseManager,
        alerts_config: Optional[Dict[str, Any]] = None,
    ):
        self._db = db_manager
        self._cfg = alerts_config or {}
        logger.debug(
            "AlertManager initialised – email_enabled=%s",
            self._cfg.get("email_enabled", False),
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    def create_alert(
        self,
        client_id: int,
        rule_match: Dict[str, Any],
        data: Dict[str, Any],
    ) -> Optional[int]:
        """
        Process a rule match and create an alert if not a duplicate.

        Steps:
          1. Check deduplication window – skip if same rule fired recently.
          2. Store alert in the database.
          3. Write to alerts.log.
          4. Send email notification if configured.

        Args:
            client_id:  Database ID of the reporting client.
            rule_match: Rule match dict from RuleEngine.evaluate().
            data:       Original collected-data payload (for context).

        Returns:
            New alert database ID, or None if deduplicated / failed.
        """
        rule_name = rule_match.get("name", "unknown_rule")
        severity = rule_match.get("severity", "LOW")
        description = rule_match.get("description", "")
        evidence = rule_match.get("evidence", {})

        # ── Deduplication check ────────────────────────────────────────────
        if self._db.alert_exists_recent(
            client_id, rule_name, DEDUP_WINDOW_SECONDS
        ):
            logger.debug(
                "Duplicate alert suppressed – client_id=%d, rule=%s",
                client_id,
                rule_name,
            )
            return None

        # ── Persist in DB ──────────────────────────────────────────────────
        full_description = self._build_description(description, evidence, data)

        try:
            alert_id = self._db.add_alert(
                client_id=client_id,
                severity=severity,
                rule_name=rule_name,
                description=full_description,
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Failed to store alert in DB: %s", exc)
            return None

        # ── File log ───────────────────────────────────────────────────────
        self._log_to_file(
            alert_id=alert_id,
            client_id=client_id,
            rule_name=rule_name,
            severity=severity,
            description=full_description,
            data=data,
        )

        # ── Email notification ─────────────────────────────────────────────
        if self._cfg.get("email_enabled", False):
            self._send_email(
                alert_id=alert_id,
                rule_name=rule_name,
                severity=severity,
                description=full_description,
                client_id=client_id,
            )

        logger.info(
            "Alert created – id=%d, rule=%s, severity=%s, client=%d",
            alert_id,
            rule_name,
            severity,
            client_id,
        )
        return alert_id

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Return the most recent alerts from the database.

        Args:
            limit: Maximum number of alerts to return.

        Returns:
            List of alert dicts ordered by timestamp descending.
        """
        return self._db.get_alerts(limit=limit)

    def process_all_rules(
        self,
        client_id: int,
        rule_matches: List[Dict[str, Any]],
        data: Dict[str, Any],
    ) -> List[int]:
        """
        Batch-create alerts for every matched rule.

        Args:
            client_id:    Source client database ID.
            rule_matches: List of rule match dicts from RuleEngine.evaluate().
            data:         Original collected payload.

        Returns:
            List of created alert IDs (None entries omitted).
        """
        created_ids: List[int] = []
        for match in rule_matches:
            alert_id = self.create_alert(client_id, match, data)
            if alert_id is not None:
                created_ids.append(alert_id)
        return created_ids

    # ── Private helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _build_description(
        base_description: str,
        evidence: Dict[str, Any],
        data: Dict[str, Any],
    ) -> str:
        """Compose a detailed alert description from rule and evidence."""
        hostname = data.get("hostname", "unknown")
        timestamp = data.get("timestamp", datetime.now().isoformat())

        parts = [
            f"Host: {hostname}",
            f"Time: {timestamp}",
            base_description,
        ]

        if evidence:
            # Add brief evidence summary (avoid dumping huge dicts)
            for key, val in list(evidence.items())[:5]:
                if isinstance(val, (int, float, str, bool)):
                    parts.append(f"{key}: {val}")

        return " | ".join(parts)

    def _log_to_file(
        self,
        alert_id: int,
        client_id: int,
        rule_name: str,
        severity: str,
        description: str,
        data: Dict[str, Any],
    ) -> None:
        """Write a structured alert entry to alerts.log."""
        level_int = SEVERITY_MAP.get(severity.upper(), LOW)
        msg = (
            f"ALERT#{alert_id} client_id={client_id} "
            f"rule={rule_name} severity={severity} | {description}"
        )
        # Map A-HIDS severity to Python logging level
        py_level = {
            LOW: logging.INFO,
            MEDIUM: logging.WARNING,
            HIGH: logging.ERROR,
            CRITICAL: logging.CRITICAL,
        }.get(level_int, logging.WARNING)

        _alert_file_logger.log(py_level, msg)

    def _send_email(
        self,
        alert_id: int,
        rule_name: str,
        severity: str,
        description: str,
        client_id: int,
    ) -> None:
        """
        Send an email notification for a new alert.

        Silently logs and returns on any SMTP error so that email
        failures never interrupt the main processing pipeline.
        """
        smtp_server = self._cfg.get("smtp_server", "")
        smtp_port = int(self._cfg.get("smtp_port", 587))
        email_from = self._cfg.get("email_from", "")
        email_to = self._cfg.get("email_to", "")
        email_password = self._cfg.get("email_password", "")

        if not all([smtp_server, email_from, email_to]):
            logger.warning("Email config incomplete – skipping notification")
            return

        subject = (
            f"[A-HIDS] {severity} Alert: {rule_name} "
            f"(client_id={client_id})"
        )
        body = (
            f"A-HIDS Security Alert\n"
            f"{'=' * 50}\n\n"
            f"Alert ID  : {alert_id}\n"
            f"Severity  : {severity}\n"
            f"Rule      : {rule_name}\n"
            f"Client ID : {client_id}\n"
            f"Time      : {datetime.now().isoformat()}\n"
            f"Hostname  : {socket.gethostname()}\n\n"
            f"Description:\n{description}\n"
        )

        msg = MIMEMultipart()
        msg["From"] = email_from
        msg["To"] = email_to
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        try:
            with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.login(email_from, email_password)
                server.sendmail(email_from, email_to, msg.as_string())
            logger.info(
                "Email notification sent for alert %d to %s",
                alert_id,
                email_to,
            )
        except smtplib.SMTPException as exc:
            logger.warning("SMTP error sending alert email: %s", exc)
        except OSError as exc:
            logger.warning("Network error sending alert email: %s", exc)
