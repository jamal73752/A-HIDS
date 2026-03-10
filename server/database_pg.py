"""
database_pg.py - PostgreSQL database adapter for A-HIDS server.

Provides the same public interface as DatabaseManager (database.py) but
uses PostgreSQL via psycopg2-binary with connection pooling.

Falls back gracefully if psycopg2 is not installed.
"""

import json
import logging
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, Generator, List, Optional

logger = logging.getLogger(__name__)

# ── Schema DDL (PostgreSQL) ────────────────────────────────────────────────────

_DDL_PG = """
CREATE TABLE IF NOT EXISTS clients (
    id          SERIAL PRIMARY KEY,
    hostname    TEXT    NOT NULL UNIQUE,
    ip_address  TEXT,
    os_info     TEXT,
    last_seen   TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS events (
    id          SERIAL PRIMARY KEY,
    client_id   INTEGER NOT NULL REFERENCES clients(id),
    timestamp   TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,
    severity    TEXT    NOT NULL DEFAULT 'LOW',
    description TEXT,
    data        TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id             SERIAL PRIMARY KEY,
    client_id      INTEGER NOT NULL REFERENCES clients(id),
    timestamp      TEXT    NOT NULL,
    severity       TEXT    NOT NULL,
    rule_name      TEXT    NOT NULL,
    description    TEXT,
    acknowledged   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rules (
    id          SERIAL PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT,
    condition   TEXT    NOT NULL,
    action      TEXT    NOT NULL DEFAULT 'alert',
    enabled     INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS token_blacklist (
    id          SERIAL PRIMARY KEY,
    token_hash  TEXT    NOT NULL UNIQUE,
    revoked_at  TEXT    NOT NULL,
    reason      TEXT
);

CREATE TABLE IF NOT EXISTS client_tokens (
    id          SERIAL PRIMARY KEY,
    client_id   TEXT    NOT NULL,
    token_hash  TEXT    NOT NULL UNIQUE,
    issued_at   TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL,
    is_active   INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_events_client_pg   ON events  (client_id);
CREATE INDEX IF NOT EXISTS idx_events_ts_pg       ON events  (timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_client_pg   ON alerts  (client_id);
CREATE INDEX IF NOT EXISTS idx_alerts_ts_pg       ON alerts  (timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity_pg ON alerts  (severity);
"""


class PostgresDatabaseManager:
    """
    PostgreSQL-backed database manager with a connection pool.

    Exposes the same public methods as ``server.database.DatabaseManager``
    so that the two implementations are interchangeable.

    Args:
        pg_config: Dict with keys ``host``, ``port``, ``database``,
                   ``user``, ``password``, and optionally ``pool_size``.
    """

    def __init__(self, pg_config: Dict[str, Any]):
        self._cfg = pg_config
        self._pool = None
        self._connect_pool()
        self.init_db()
        logger.info("PostgresDatabaseManager ready")

    # ── Connection pool ────────────────────────────────────────────────────────

    def _connect_pool(self) -> None:
        """Initialise a SimpleConnectionPool from psycopg2."""
        try:
            from psycopg2 import pool as pg_pool

            self._pool = pg_pool.SimpleConnectionPool(
                minconn=1,
                maxconn=self._cfg.get("pool_size", 10),
                host=self._cfg.get("host", "localhost"),
                port=int(self._cfg.get("port", 5432)),
                dbname=self._cfg.get("database", "ahids"),
                user=self._cfg.get("user", "ahids_user"),
                password=self._cfg.get("password", ""),
            )
            logger.info(
                "PostgreSQL pool created: %s:%s/%s",
                self._cfg.get("host"),
                self._cfg.get("port"),
                self._cfg.get("database"),
            )
        except ImportError:
            raise RuntimeError(
                "psycopg2-binary is required for PostgreSQL support. "
                "Install it with: pip install psycopg2-binary"
            )
        except Exception as exc:
            raise RuntimeError(f"PostgreSQL connection failed: {exc}") from exc

    @contextmanager
    def _connect(self) -> Generator[Any, None, None]:
        """Yield a connection from the pool and return it when done."""
        import psycopg2.extras

        conn = self._pool.getconn()
        conn.autocommit = False
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    # ── Initialisation ─────────────────────────────────────────────────────────

    def init_db(self) -> None:
        """Create all tables and indexes if they do not already exist."""
        with self._connect() as conn:
            with conn.cursor() as cur:
                for statement in _DDL_PG.split(";"):
                    stmt = statement.strip()
                    if stmt:
                        cur.execute(stmt)
        logger.debug("PostgreSQL schema initialised")

    # ── Clients ────────────────────────────────────────────────────────────────

    def add_client(
        self,
        hostname: str,
        ip_address: str = "",
        os_info: str = "",
    ) -> int:
        """Insert or update a client record. Returns row ID."""
        now = datetime.now().isoformat()
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM clients WHERE hostname = %s", (hostname,)
                )
                row = cur.fetchone()
                if row:
                    cur.execute(
                        "UPDATE clients SET ip_address=%s, os_info=%s, "
                        "last_seen=%s, status='active' WHERE id=%s",
                        (ip_address, os_info, now, row[0]),
                    )
                    return row[0]
                cur.execute(
                    "INSERT INTO clients (hostname, ip_address, os_info, "
                    "last_seen, status) VALUES (%s,%s,%s,%s,'active') RETURNING id",
                    (hostname, ip_address, os_info, now),
                )
                return cur.fetchone()[0]

    def get_clients(self) -> List[Dict[str, Any]]:
        """Return all client records as a list of dicts."""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, hostname, ip_address, os_info, last_seen, status "
                    "FROM clients ORDER BY last_seen DESC"
                )
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_client_by_hostname(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Return a single client dict by hostname, or None."""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, hostname, ip_address, os_info, last_seen, status "
                    "FROM clients WHERE hostname=%s",
                    (hostname,),
                )
                row = cur.fetchone()
                if row is None:
                    return None
                cols = [d[0] for d in cur.description]
                return dict(zip(cols, row))

    # ── Events ─────────────────────────────────────────────────────────────────

    def add_event(
        self,
        client_id: int,
        event_type: str,
        severity: str = "LOW",
        description: str = "",
        data: Any = None,
    ) -> int:
        """Insert a security event. Returns row ID."""
        now = datetime.now().isoformat()
        data_json = json.dumps(data) if data is not None else None
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO events (client_id, timestamp, event_type, "
                    "severity, description, data) VALUES (%s,%s,%s,%s,%s,%s) RETURNING id",
                    (client_id, now, event_type, severity, description, data_json),
                )
                return cur.fetchone()[0]

    def get_events(
        self,
        client_id: Optional[int] = None,
        limit: int = 500,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve stored events with optional filters."""
        query = (
            "SELECT id, client_id, timestamp, event_type, severity, "
            "description, data FROM events WHERE 1=1"
        )
        params: List[Any] = []

        if client_id is not None:
            query += " AND client_id=%s"
            params.append(client_id)
        if severity:
            query += " AND severity=%s"
            params.append(severity.upper())

        query += " ORDER BY timestamp DESC LIMIT %s"
        params.append(limit)

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]

    # ── Alerts ─────────────────────────────────────────────────────────────────

    def add_alert(
        self,
        client_id: int,
        severity: str,
        rule_name: str,
        description: str = "",
    ) -> int:
        """Insert a new alert record. Returns row ID."""
        now = datetime.now().isoformat()
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO alerts (client_id, timestamp, severity, "
                    "rule_name, description, acknowledged) "
                    "VALUES (%s,%s,%s,%s,%s,0) RETURNING id",
                    (client_id, now, severity.upper(), rule_name, description),
                )
                return cur.fetchone()[0]

    def get_alerts(
        self,
        severity: Optional[str] = None,
        client_id: Optional[int] = None,
        limit: int = 200,
        unacknowledged_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """Retrieve alerts with optional filters."""
        query = (
            "SELECT id, client_id, timestamp, severity, rule_name, "
            "description, acknowledged FROM alerts WHERE 1=1"
        )
        params: List[Any] = []

        if severity:
            query += " AND severity=%s"
            params.append(severity.upper())
        if client_id is not None:
            query += " AND client_id=%s"
            params.append(client_id)
        if unacknowledged_only:
            query += " AND acknowledged=0"

        query += " ORDER BY timestamp DESC LIMIT %s"
        params.append(limit)

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]

    def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark an alert as acknowledged. Returns True if a row was updated."""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE alerts SET acknowledged=1 WHERE id=%s", (alert_id,)
                )
                return cur.rowcount > 0

    def alert_exists_recent(
        self, client_id: int, rule_name: str, within_seconds: int = 300
    ) -> bool:
        """Check for a duplicate alert within the deduplication window."""
        cutoff = (datetime.now() - timedelta(seconds=within_seconds)).isoformat()
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM alerts WHERE client_id=%s AND rule_name=%s "
                    "AND timestamp > %s LIMIT 1",
                    (client_id, rule_name, cutoff),
                )
                return cur.fetchone() is not None

    # ── Rules ──────────────────────────────────────────────────────────────────

    def add_rule(
        self,
        name: str,
        description: str,
        condition: str,
        action: str = "alert",
        enabled: bool = True,
    ) -> int:
        """Insert or update a detection rule. Returns row ID."""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO rules (name, description, condition, action, enabled) "
                    "VALUES (%s,%s,%s,%s,%s) "
                    "ON CONFLICT (name) DO UPDATE SET "
                    "description=EXCLUDED.description, condition=EXCLUDED.condition, "
                    "action=EXCLUDED.action, enabled=EXCLUDED.enabled RETURNING id",
                    (name, description, condition, action, int(enabled)),
                )
                return cur.fetchone()[0]

    def get_rules(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        """Return all stored rules as dicts."""
        query = "SELECT id, name, description, condition, action, enabled FROM rules"
        if enabled_only:
            query += " WHERE enabled=1"
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(query)
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]

    # ── Statistics ─────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregated statistics for the dashboard."""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM events")
                total_events = cur.fetchone()[0]

                cur.execute("SELECT COUNT(*) FROM alerts")
                total_alerts = cur.fetchone()[0]

                cur.execute("SELECT COUNT(*) FROM clients WHERE status='active'")
                active_clients = cur.fetchone()[0]

                cur.execute(
                    "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
                )
                alerts_by_severity = {row[0]: row[1] for row in cur.fetchall()}

                cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
                cur.execute(
                    "SELECT COUNT(*) FROM alerts WHERE timestamp > %s", (cutoff,)
                )
                recent_alerts = cur.fetchone()[0]

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
        """Store a new client token record."""
        now = datetime.now().isoformat()
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO client_tokens "
                    "(client_id, token_hash, issued_at, expires_at, is_active) "
                    "VALUES (%s,%s,%s,%s,1) ON CONFLICT (token_hash) DO NOTHING",
                    (client_id, token_hash, now, expires_at),
                )

    def is_token_revoked(self, token_hash: str) -> bool:
        """Return True if *token_hash* is in the blacklist."""
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM token_blacklist WHERE token_hash=%s LIMIT 1",
                    (token_hash,),
                )
                return cur.fetchone() is not None

    def revoke_token(self, token_hash: str, reason: str = "revoked") -> None:
        """Add *token_hash* to the blacklist."""
        now = datetime.now().isoformat()
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO token_blacklist (token_hash, revoked_at, reason) "
                    "VALUES (%s,%s,%s) ON CONFLICT (token_hash) DO NOTHING",
                    (token_hash, now, reason),
                )
