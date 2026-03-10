"""
database.py - SQLite database manager for A-HIDS server.

Provides the DatabaseManager class which handles all persistence
operations: clients, events, alerts, detection rules, and JWT token
blacklist / client-token tables.

A factory function ``create_database(config)`` selects between
SQLite (default) and PostgreSQL based on configuration.
Uses context managers for safe connection handling.
"""

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, Generator, List, Optional

logger = logging.getLogger(__name__)

# ── Schema DDL ────────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS clients (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname    TEXT    NOT NULL,
    ip_address  TEXT,
    os_info     TEXT,
    last_seen   TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id   INTEGER NOT NULL,
    timestamp   TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,
    severity    TEXT    NOT NULL DEFAULT 'LOW',
    description TEXT,
    data        TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id      INTEGER NOT NULL,
    timestamp      TEXT    NOT NULL,
    severity       TEXT    NOT NULL,
    rule_name      TEXT    NOT NULL,
    description    TEXT,
    acknowledged   INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (client_id) REFERENCES clients(id)
);

CREATE TABLE IF NOT EXISTS rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT,
    condition   TEXT    NOT NULL,
    action      TEXT    NOT NULL DEFAULT 'alert',
    enabled     INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_events_client   ON events  (client_id);
CREATE INDEX IF NOT EXISTS idx_events_ts       ON events  (timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_client   ON alerts  (client_id);
CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts  (timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts  (severity);

CREATE TABLE IF NOT EXISTS token_blacklist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash  TEXT    NOT NULL UNIQUE,
    revoked_at  TEXT    NOT NULL,
    reason      TEXT
);

CREATE TABLE IF NOT EXISTS client_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id   TEXT    NOT NULL,
    token_hash  TEXT    NOT NULL UNIQUE,
    issued_at   TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL,
    is_active   INTEGER NOT NULL DEFAULT 1
);
"""


class DatabaseManager:
    """
    Manages the A-HIDS SQLite database.

    All methods that write to the database commit automatically.
    Read-only methods do not require a transaction.

    When *db_path* is ``:memory:``, a single shared connection is
    maintained throughout the lifetime of the instance so that tables
    created by :meth:`init_db` remain visible to subsequent calls.

    Args:
        db_path: Path to the SQLite database file.
                 Use ``:memory:`` for in-process testing.
    """

    def __init__(self, db_path: str = "ahids.db"):
        self._db_path = db_path
        # For in-memory databases we keep a single open connection so
        # that the schema survives across method calls.
        if db_path == ":memory:":
            self._shared_conn: sqlite3.Connection | None = sqlite3.connect(":memory:", check_same_thread=False)
            self._shared_conn.row_factory = sqlite3.Row
            self._shared_conn.execute("PRAGMA journal_mode=WAL")
            self._shared_conn.execute("PRAGMA foreign_keys=ON")
        else:
            self._shared_conn = None
        self.init_db()
        logger.info("DatabaseManager ready – %s", db_path)

    # ── Connection helper ──────────────────────────────────────────────────────

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """
        Yield a sqlite3 connection and guarantee it is closed afterwards.

        For ``:memory:`` databases the shared persistent connection is
        yielded directly (not closed at the end of the ``with`` block).
        For file-based databases a fresh connection is opened and closed.

        Row factory is set so rows behave like dicts (sqlite3.Row).
        """
        if self._shared_conn is not None:
            # In-memory: yield the single shared connection without closing
            yield self._shared_conn
        else:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            try:
                yield conn
            finally:
                conn.close()

    # ── Initialisation ─────────────────────────────────────────────────────────

    def init_db(self) -> None:
        """Create all tables and indexes if they do not already exist."""
        with self._connect() as conn:
            conn.executescript(_DDL)
            conn.commit()
        logger.debug("Database schema initialised")

    # ── Clients ────────────────────────────────────────────────────────────────

    def add_client(
        self,
        hostname: str,
        ip_address: str = "",
        os_info: str = "",
    ) -> int:
        """
        Insert a new client record, or update last_seen if it already exists.

        Args:
            hostname:   Host FQDN or short name.
            ip_address: Primary IP address of the client.
            os_info:    Operating system description string.

        Returns:
            The client's database row ID.
        """
        now = datetime.now().isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT id FROM clients WHERE hostname = ?", (hostname,)
            )
            row = cur.fetchone()
            if row:
                conn.execute(
                    "UPDATE clients SET ip_address=?, os_info=?, "
                    "last_seen=?, status='active' WHERE id=?",
                    (ip_address, os_info, now, row["id"]),
                )
                conn.commit()
                return row["id"]

            cur = conn.execute(
                "INSERT INTO clients (hostname, ip_address, os_info, "
                "last_seen, status) VALUES (?,?,?,?,'active')",
                (hostname, ip_address, os_info, now),
            )
            conn.commit()
            return cur.lastrowid

    def update_client(self, client_id: int, **kwargs) -> None:
        """
        Update arbitrary columns on a client row.

        Args:
            client_id: Target client ID.
            **kwargs:  Column names and new values.
        """
        if not kwargs:
            return
        cols = ", ".join(f"{k}=?" for k in kwargs)
        vals = list(kwargs.values()) + [client_id]
        with self._connect() as conn:
            conn.execute(f"UPDATE clients SET {cols} WHERE id=?", vals)
            conn.commit()

    def get_clients(self) -> List[Dict[str, Any]]:
        """Return all client records as a list of dicts."""
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM clients ORDER BY last_seen DESC").fetchall()
        return [dict(r) for r in rows]

    def get_client_by_hostname(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Return a single client dict by hostname, or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM clients WHERE hostname=?", (hostname,)
            ).fetchone()
        return dict(row) if row else None

    # ── Events ─────────────────────────────────────────────────────────────────

    def add_event(
        self,
        client_id: int,
        event_type: str,
        severity: str = "LOW",
        description: str = "",
        data: Any = None,
    ) -> int:
        """
        Store a security event.

        Args:
            client_id:   ID of the client that generated the event.
            event_type:  Category string (e.g. "process", "network").
            severity:    One of LOW / MEDIUM / HIGH / CRITICAL.
            description: Human-readable summary.
            data:        Arbitrary dict/list serialised to JSON.

        Returns:
            The new event row ID.
        """
        now = datetime.now().isoformat()
        data_json = json.dumps(data) if data is not None else None
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO events (client_id, timestamp, event_type, "
                "severity, description, data) VALUES (?,?,?,?,?,?)",
                (client_id, now, event_type, severity, description, data_json),
            )
            conn.commit()
            return cur.lastrowid

    def get_events(
        self,
        client_id: Optional[int] = None,
        limit: int = 500,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve stored events, optionally filtered.

        Args:
            client_id: Filter to a specific client (None = all clients).
            limit:     Maximum number of rows returned.
            severity:  Filter by severity string.

        Returns:
            List of event dicts ordered by timestamp descending.
        """
        query = "SELECT * FROM events WHERE 1=1"
        params: List[Any] = []

        if client_id is not None:
            query += " AND client_id=?"
            params.append(client_id)
        if severity:
            query += " AND severity=?"
            params.append(severity.upper())

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ── Alerts ─────────────────────────────────────────────────────────────────

    def add_alert(
        self,
        client_id: int,
        severity: str,
        rule_name: str,
        description: str = "",
    ) -> int:
        """
        Insert a new alert record.

        Args:
            client_id:   Source client ID.
            severity:    Alert severity string.
            rule_name:   Name of the detection rule that fired.
            description: Human-readable alert detail.

        Returns:
            New alert row ID.
        """
        now = datetime.now().isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO alerts (client_id, timestamp, severity, "
                "rule_name, description, acknowledged) VALUES (?,?,?,?,?,0)",
                (client_id, now, severity.upper(), rule_name, description),
            )
            conn.commit()
            return cur.lastrowid

    def get_alerts(
        self,
        severity: Optional[str] = None,
        client_id: Optional[int] = None,
        limit: int = 200,
        unacknowledged_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve alerts with optional filters.

        Returns:
            List of alert dicts ordered by timestamp descending.
        """
        query = "SELECT * FROM alerts WHERE 1=1"
        params: List[Any] = []

        if severity:
            query += " AND severity=?"
            params.append(severity.upper())
        if client_id is not None:
            query += " AND client_id=?"
            params.append(client_id)
        if unacknowledged_only:
            query += " AND acknowledged=0"

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def acknowledge_alert(self, alert_id: int) -> bool:
        """
        Mark an alert as acknowledged.

        Args:
            alert_id: Target alert row ID.

        Returns:
            True if a row was updated, False if the ID did not exist.
        """
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,)
            )
            conn.commit()
            return cur.rowcount > 0

    def alert_exists_recent(
        self, client_id: int, rule_name: str, within_seconds: int = 300
    ) -> bool:
        """
        Check for a duplicate alert within the deduplication window.

        Args:
            client_id:      Client to check.
            rule_name:      Rule that fired.
            within_seconds: Deduplication window in seconds (default 5 min).

        Returns:
            True if a matching alert exists within the window.
        """
        from datetime import timedelta
        cutoff = (
            datetime.now() - timedelta(seconds=within_seconds)
        ).isoformat()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id FROM alerts WHERE client_id=? AND rule_name=? "
                "AND timestamp > ?",
                (client_id, rule_name, cutoff),
            ).fetchone()
        return row is not None

    # ── Rules ──────────────────────────────────────────────────────────────────

    def add_rule(
        self,
        name: str,
        description: str,
        condition: str,
        action: str = "alert",
        enabled: bool = True,
    ) -> int:
        """
        Insert or replace a detection rule.

        Returns:
            New rule row ID.
        """
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT OR REPLACE INTO rules (name, description, condition, "
                "action, enabled) VALUES (?,?,?,?,?)",
                (name, description, condition, action, int(enabled)),
            )
            conn.commit()
            return cur.lastrowid

    def get_rules(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        """Return all stored rules as dicts."""
        query = "SELECT * FROM rules"
        if enabled_only:
            query += " WHERE enabled=1"
        with self._connect() as conn:
            rows = conn.execute(query).fetchall()
        return [dict(r) for r in rows]

    # ── Statistics ─────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """
        Return aggregated statistics for the dashboard.

        Returns:
            Dict with total_events, total_alerts, active_clients,
            alerts_by_severity, and recent_alert_count.
        """
        with self._connect() as conn:
            total_events = conn.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()[0]

            total_alerts = conn.execute(
                "SELECT COUNT(*) FROM alerts"
            ).fetchone()[0]

            active_clients = conn.execute(
                "SELECT COUNT(*) FROM clients WHERE status='active'"
            ).fetchone()[0]

            severity_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM alerts "
                "GROUP BY severity"
            ).fetchall()

            recent_alerts = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE timestamp > "
                "datetime('now','-24 hours')"
            ).fetchone()[0]

        alerts_by_severity = {row["severity"]: row["cnt"] for row in severity_rows}

        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "active_clients": active_clients,
            "alerts_by_severity": alerts_by_severity,
            "recent_alert_count": recent_alerts,
        }

    # ── Token management ───────────────────────────────────────────────────────

    def store_client_token(
        self, client_id: str, token_hash: str, expires_at: str
    ) -> None:
        """
        Persist a JWT token hash for *client_id*.

        Args:
            client_id:  Client identifier string.
            token_hash: SHA-256 hex digest of the raw JWT.
            expires_at: ISO-format expiry timestamp.
        """
        now = datetime.now().isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO client_tokens "
                "(client_id, token_hash, issued_at, expires_at, is_active) "
                "VALUES (?,?,?,?,1)",
                (client_id, token_hash, now, expires_at),
            )
            conn.commit()

    def is_token_revoked(self, token_hash: str) -> bool:
        """
        Return True if *token_hash* appears in the blacklist.

        Args:
            token_hash: SHA-256 hex digest of the JWT to check.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id FROM token_blacklist WHERE token_hash=?",
                (token_hash,),
            ).fetchone()
        return row is not None

    def revoke_token(self, token_hash: str, reason: str = "revoked") -> None:
        """
        Add *token_hash* to the blacklist.

        Args:
            token_hash: SHA-256 hex digest of the JWT.
            reason:     Human-readable revocation reason.
        """
        now = datetime.now().isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO token_blacklist "
                "(token_hash, revoked_at, reason) VALUES (?,?,?)",
                (token_hash, now, reason),
            )
            conn.commit()


# ── Factory function ───────────────────────────────────────────────────────────


def create_database(config: Dict[str, Any]) -> "DatabaseManager":
    """
    Return the appropriate database manager based on *config*.

    Selects PostgreSQL when ``server.database_type`` is ``"postgresql"``
    and psycopg2 is installed; falls back to SQLite otherwise.

    Args:
        config: Full application configuration dict.

    Returns:
        A configured ``DatabaseManager`` (SQLite) or
        ``PostgresDatabaseManager`` (PostgreSQL) instance.
    """
    server_cfg = config.get("server", {})
    db_type = server_cfg.get("database_type", "sqlite").lower()

    if db_type == "postgresql":
        pg_cfg = server_cfg.get("postgresql", {})
        try:
            from server.db.database_pg import PostgresDatabaseManager
            logger.info("Using PostgreSQL database backend")
            return PostgresDatabaseManager(pg_cfg)  # type: ignore[return-value]
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(
                "PostgreSQL unavailable (%s) – falling back to SQLite.", exc
            )

    db_path = server_cfg.get("database", "ahids.db")
    logger.info("Using SQLite database backend: %s", db_path)
    return DatabaseManager(db_path)
