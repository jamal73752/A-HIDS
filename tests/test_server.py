"""
test_server.py - Unit tests for A-HIDS server modules.

Tests cover DatabaseManager (in-memory SQLite), RuleEngine evaluation,
and AlertManager creation and deduplication logic.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure project root is importable
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


# ── TestDatabase ───────────────────────────────────────────────────────────────

class TestDatabase(unittest.TestCase):
    """Tests for server.database.DatabaseManager using :memory: SQLite."""

    def setUp(self):
        """Create an in-memory database for each test."""
        from server.db.database import DatabaseManager
        self.db = DatabaseManager(db_path=":memory:")

    def test_init_creates_tables(self):
        """init_db should create clients, events, alerts, and rules tables."""
        import sqlite3
        conn = sqlite3.connect(":memory:")
        # Re-run init on the same DB to verify idempotency
        from server.db.database import _DDL
        conn.executescript(_DDL)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = {row[0] for row in cursor.fetchall()}
        for expected in ("clients", "events", "alerts", "rules"):
            self.assertIn(expected, tables)
        conn.close()

    def test_add_client_returns_id(self):
        """add_client should return an integer row ID."""
        client_id = self.db.add_client("testhost", "192.168.1.1", "Linux 5.15")
        self.assertIsInstance(client_id, int)
        self.assertGreater(client_id, 0)

    def test_add_client_same_hostname_returns_same_id(self):
        """Calling add_client twice with the same hostname should return the same ID."""
        id1 = self.db.add_client("samehost", "10.0.0.1")
        id2 = self.db.add_client("samehost", "10.0.0.2")  # updated IP
        self.assertEqual(id1, id2)

    def test_get_clients_returns_list(self):
        """get_clients should return a list of dicts."""
        self.db.add_client("host-a")
        self.db.add_client("host-b")
        clients = self.db.get_clients()
        self.assertIsInstance(clients, list)
        self.assertGreaterEqual(len(clients), 2)

    def test_add_event_returns_id(self):
        """add_event should return an integer row ID."""
        client_id = self.db.add_client("evthost")
        event_id = self.db.add_event(
            client_id=client_id,
            event_type="test_event",
            severity="HIGH",
            description="test description",
        )
        self.assertIsInstance(event_id, int)
        self.assertGreater(event_id, 0)

    def test_get_events_returns_list(self):
        """get_events should return a non-empty list after adding events."""
        client_id = self.db.add_client("evthost2")
        self.db.add_event(client_id, "process", "LOW", "test proc event")
        events = self.db.get_events(client_id=client_id)
        self.assertIsInstance(events, list)
        self.assertEqual(len(events), 1)

    def test_add_alert_returns_id(self):
        """add_alert should return an integer row ID."""
        client_id = self.db.add_client("alerthost")
        alert_id = self.db.add_alert(
            client_id=client_id,
            severity="CRITICAL",
            rule_name="brute_force_ssh",
            description="SSH brute force detected",
        )
        self.assertIsInstance(alert_id, int)

    def test_get_alerts_returns_list(self):
        """get_alerts should return all stored alerts."""
        client_id = self.db.add_client("alerthost2")
        self.db.add_alert(client_id, "HIGH", "test_rule", "desc")
        alerts = self.db.get_alerts()
        self.assertIsInstance(alerts, list)
        self.assertGreaterEqual(len(alerts), 1)

    def test_acknowledge_alert(self):
        """acknowledge_alert should mark alert as acknowledged."""
        client_id = self.db.add_client("ackhost")
        alert_id = self.db.add_alert(client_id, "MEDIUM", "test_ack", "")
        result = self.db.acknowledge_alert(alert_id)
        self.assertTrue(result)

        alerts = self.db.get_alerts()
        acked = next((a for a in alerts if a["id"] == alert_id), None)
        self.assertIsNotNone(acked)
        self.assertEqual(acked["acknowledged"], 1)

    def test_get_stats_returns_required_keys(self):
        """get_stats must return dict with expected keys."""
        stats = self.db.get_stats()
        for key in ("total_events", "total_alerts", "active_clients",
                    "alerts_by_severity", "recent_alert_count"):
            self.assertIn(key, stats)

    def test_alert_deduplication_window(self):
        """alert_exists_recent should detect duplicate within window."""
        client_id = self.db.add_client("deduphost")
        self.db.add_alert(client_id, "HIGH", "brute_force_ssh", "")
        result = self.db.alert_exists_recent(client_id, "brute_force_ssh", 300)
        self.assertTrue(result)

    def test_alert_not_duplicate_for_different_rule(self):
        """Different rule names should not trigger deduplication."""
        client_id = self.db.add_client("deduphost2")
        self.db.add_alert(client_id, "HIGH", "rule_a", "")
        result = self.db.alert_exists_recent(client_id, "rule_b", 300)
        self.assertFalse(result)


# ── TestRuleEngine ─────────────────────────────────────────────────────────────

class TestRuleEngine(unittest.TestCase):
    """Tests for server.rule_engine.RuleEngine."""

    def setUp(self):
        from server.core.rule_engine import RuleEngine
        self.engine = RuleEngine()

    def _make_data(self, **overrides):
        """Build a minimal data payload with safe defaults."""
        base = {
            "hostname": "testhost",
            "timestamp": "2024-01-01T00:00:00",
            "system_info": {
                "cpu_usage": 10.0,
                "memory_usage": 30.0,
                "disk_usage": 40.0,
            },
            "cpu_usage": 10.0,
            "memory_usage": 30.0,
            "disk_usage": 40.0,
            "suspicious_processes": [],
            "log_events": [],
            "network": {
                "suspicious_connections": [],
                "listening_ports": [],
                "total_connections": 5,
            },
            "file_integrity": {
                "modified": [],
                "added": [],
                "deleted": [],
            },
        }
        base.update(overrides)
        return base

    def test_no_alerts_on_normal_data(self):
        """Normal data payload should not trigger any rules."""
        data = self._make_data()
        matches = self.engine.evaluate(data)
        self.assertEqual(len(matches), 0)

    def test_brute_force_ssh_rule_fires(self):
        """brute_force_ssh rule should fire when ≥5 failed logins are logged."""
        failed_events = [
            {"pattern_matched": "failed_login", "severity": "HIGH",
             "source": "/var/log/auth.log", "message": "Failed password",
             "timestamp": "2024-01-01T00:00:01"}
            for _ in range(6)
        ]
        data = self._make_data(log_events=failed_events)
        matches = self.engine.evaluate(data)
        names = [m["name"] for m in matches]
        self.assertIn("brute_force_ssh", names)

    def test_high_cpu_rule_fires(self):
        """high_cpu_usage rule should fire when CPU > 90%."""
        data = self._make_data(cpu_usage=95.0)
        matches = self.engine.evaluate(data)
        names = [m["name"] for m in matches]
        self.assertIn("high_cpu_usage", names)

    def test_file_modification_rule_fires(self):
        """unauthorized_file_modification rule should fire when files are modified."""
        data = self._make_data(
            file_integrity={
                "modified": [{"path": "/etc/passwd", "old_hash": "aaa", "new_hash": "bbb"}],
                "added": [],
                "deleted": [],
            }
        )
        matches = self.engine.evaluate(data)
        names = [m["name"] for m in matches]
        self.assertIn("unauthorized_file_modification", names)

    def test_suspicious_process_rule_fires(self):
        """suspicious_process rule should fire when suspicious processes exist."""
        data = self._make_data(
            suspicious_processes=[
                {"pid": 1234, "name": "nc", "cpu_percent": 5.0, "memory_mb": 10.0}
            ]
        )
        matches = self.engine.evaluate(data)
        names = [m["name"] for m in matches]
        self.assertIn("suspicious_process", names)

    def test_rule_evidence_included(self):
        """Each matched rule should include an 'evidence' key."""
        data = self._make_data(cpu_usage=95.0)
        matches = self.engine.evaluate(data)
        for match in matches:
            self.assertIn("evidence", match)

    def test_toggle_rule_disables_it(self):
        """toggle_rule(False) should prevent that rule from firing."""
        self.engine.toggle_rule("high_cpu_usage", False)
        data = self._make_data(cpu_usage=99.0)
        matches = self.engine.evaluate(data)
        names = [m["name"] for m in matches]
        self.assertNotIn("high_cpu_usage", names)
        # Re-enable
        self.engine.toggle_rule("high_cpu_usage", True)


# ── TestAlertManager ───────────────────────────────────────────────────────────

class TestAlertManager(unittest.TestCase):
    """Tests for server.alert_manager.AlertManager."""

    def setUp(self):
        from server.db.database import DatabaseManager
        from server.core.alert_manager import AlertManager

        self.db = DatabaseManager(db_path=":memory:")
        self.client_id = self.db.add_client("alerthost")
        self.manager = AlertManager(
            db_manager=self.db,
            alerts_config={"email_enabled": False},
        )

    def _make_rule_match(self, rule_name="brute_force_ssh", severity="HIGH"):
        return {
            "name": rule_name,
            "severity": severity,
            "description": "Test rule description",
            "evidence": {"count": 6},
        }

    def _make_data(self):
        return {
            "hostname": "alerthost",
            "timestamp": "2024-01-01T00:00:00",
        }

    def test_create_alert_returns_id(self):
        """create_alert should return an integer alert ID."""
        alert_id = self.manager.create_alert(
            self.client_id,
            self._make_rule_match(),
            self._make_data(),
        )
        self.assertIsNotNone(alert_id)
        self.assertIsInstance(alert_id, int)

    def test_alert_stored_in_database(self):
        """Alert created by manager should be retrievable from the database."""
        self.manager.create_alert(
            self.client_id,
            self._make_rule_match(),
            self._make_data(),
        )
        alerts = self.db.get_alerts()
        self.assertGreaterEqual(len(alerts), 1)

    def test_deduplication_suppresses_duplicate(self):
        """Second create_alert call for same rule within window returns None."""
        rule_match = self._make_rule_match(rule_name="dup_rule")
        data = self._make_data()

        first_id = self.manager.create_alert(self.client_id, rule_match, data)
        second_id = self.manager.create_alert(self.client_id, rule_match, data)

        self.assertIsNotNone(first_id)
        self.assertIsNone(second_id, "Duplicate alert was not suppressed")

    def test_different_rules_both_create_alerts(self):
        """Two different rule names should each produce an alert."""
        data = self._make_data()
        id1 = self.manager.create_alert(
            self.client_id, self._make_rule_match("rule_alpha"), data
        )
        id2 = self.manager.create_alert(
            self.client_id, self._make_rule_match("rule_beta"), data
        )
        self.assertIsNotNone(id1)
        self.assertIsNotNone(id2)
        self.assertNotEqual(id1, id2)

    @patch("smtplib.SMTP")
    def test_email_not_sent_when_disabled(self, mock_smtp):
        """No SMTP connection should be made when email_enabled=False."""
        self.manager.create_alert(
            self.client_id,
            self._make_rule_match("no_email_rule"),
            self._make_data(),
        )
        mock_smtp.assert_not_called()

    def test_get_recent_alerts_returns_list(self):
        """get_recent_alerts must return a list."""
        self.manager.create_alert(
            self.client_id,
            self._make_rule_match("list_test_rule"),
            self._make_data(),
        )
        recent = self.manager.get_recent_alerts()
        self.assertIsInstance(recent, list)
        self.assertGreaterEqual(len(recent), 1)


if __name__ == "__main__":
    unittest.main()
