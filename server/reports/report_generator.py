"""
report_generator.py - HTML security report generator for A-HIDS server.

Generates styled HTML reports summarising events, alerts, clients, and
detected threats.  Reports can be returned as strings or saved to disk.
"""

import logging
import os
from datetime import datetime
from typing import Any, Dict, List

from server.db.database import DatabaseManager

logger = logging.getLogger(__name__)

# ── HTML / CSS template ────────────────────────────────────────────────────────

_REPORT_CSS = """
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0a0e1a;
         color: #c9d1d9; margin: 0; padding: 20px; }
  h1   { color: #00ff88; border-bottom: 2px solid #00ff88; padding-bottom: 8px; }
  h2   { color: #00bcd4; margin-top: 30px; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; }
  th   { background: #1a1f2e; color: #00ff88; padding: 10px; text-align: left;
         border: 1px solid #30363d; }
  td   { padding: 8px 10px; border: 1px solid #30363d; }
  tr:nth-child(even) { background: #161b22; }
  .badge { padding: 3px 8px; border-radius: 4px; font-weight: bold;
           font-size: 0.85em; }
  .LOW      { background: #1a3a1a; color: #28a745; }
  .MEDIUM   { background: #3a3000; color: #ffc107; }
  .HIGH     { background: #3a1a00; color: #fd7e14; }
  .CRITICAL { background: #3a0000; color: #dc3545; }
  .stat-box { display: inline-block; background: #1a1f2e; border: 1px solid #30363d;
              border-radius: 8px; padding: 16px 24px; margin: 8px;
              min-width: 140px; text-align: center; }
  .stat-num { font-size: 2em; font-weight: bold; color: #00ff88; }
  .stat-lbl { font-size: 0.85em; color: #8b949e; margin-top: 4px; }
  .footer   { margin-top: 40px; font-size: 0.8em; color: #8b949e;
              border-top: 1px solid #30363d; padding-top: 12px; }
</style>
"""


def _badge(severity: str) -> str:
    """Return an HTML severity badge span."""
    sev = (severity or "LOW").upper()
    return f'<span class="badge {sev}">{sev}</span>'


def _fmt_ts(ts: str) -> str:
    """Format an ISO timestamp string for display."""
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return ts or "—"


class ReportGenerator:
    """
    Generates HTML security summary reports from the A-HIDS database.
    """

    # ── Public API ─────────────────────────────────────────────────────────────

    def generate_html_report(self, db_manager: DatabaseManager) -> str:
        """
        Build a complete HTML security report.

        Args:
            db_manager: Initialised DatabaseManager used to fetch data.

        Returns:
            Full HTML document as a string.
        """
        logger.info("Generating HTML security report…")

        stats = db_manager.get_stats()
        clients = db_manager.get_clients()
        alerts = db_manager.get_alerts(limit=50)
        events = db_manager.get_events(limit=20)

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

        sections = [
            self._html_head(now_str),
            self._section_summary(stats, now_str),
            self._section_clients(clients),
            self._section_recent_alerts(alerts),
            self._section_top_threats(alerts),
            self._section_recent_events(events),
            self._html_footer(now_str),
        ]

        return "\n".join(sections)

    @staticmethod
    def save_report(html: str, filename: str) -> str:
        """
        Save an HTML report string to a file.

        Args:
            html:     HTML content to write.
            filename: Destination file path.

        Returns:
            Absolute path of the saved file.
        """
        try:
            os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
            with open(filename, "w", encoding="utf-8") as fh:
                fh.write(html)
            logger.info("Report saved to %s", filename)
            return os.path.abspath(filename)
        except OSError as exc:
            logger.error("Failed to save report to %s: %s", filename, exc)
            raise

    # ── HTML building blocks ───────────────────────────────────────────────────

    @staticmethod
    def _html_head(generated_at: str) -> str:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>A-HIDS Security Report – {generated_at}</title>
  {_REPORT_CSS}
</head>
<body>
<h1>🛡️ A-HIDS Security Report</h1>
<p style="color:#8b949e">Generated: {generated_at}</p>
"""

    @staticmethod
    def _section_summary(stats: Dict[str, Any], period: str) -> str:
        total_events = stats.get("total_events", 0)
        total_alerts = stats.get("total_alerts", 0)
        active_clients = stats.get("active_clients", 0)
        recent_24h = stats.get("recent_alert_count", 0)
        by_sev = stats.get("alerts_by_severity", {})

        sev_rows = "".join(
            f"<tr><td>{_badge(sev)}</td><td>{cnt}</td></tr>"
            for sev, cnt in sorted(by_sev.items())
        )

        return f"""
<h2>📊 Executive Summary</h2>
<div>
  <div class="stat-box">
    <div class="stat-num">{total_events}</div>
    <div class="stat-lbl">Total Events</div>
  </div>
  <div class="stat-box">
    <div class="stat-num">{total_alerts}</div>
    <div class="stat-lbl">Total Alerts</div>
  </div>
  <div class="stat-box">
    <div class="stat-num">{active_clients}</div>
    <div class="stat-lbl">Active Clients</div>
  </div>
  <div class="stat-box">
    <div class="stat-num">{recent_24h}</div>
    <div class="stat-lbl">Alerts (24h)</div>
  </div>
</div>

<h2>Alerts by Severity</h2>
<table>
  <thead><tr><th>Severity</th><th>Count</th></tr></thead>
  <tbody>{sev_rows or '<tr><td colspan="2">No alerts</td></tr>'}</tbody>
</table>
"""

    @staticmethod
    def _section_clients(clients: List[Dict[str, Any]]) -> str:
        rows = ""
        for c in clients:
            status = c.get("status", "unknown")
            status_colour = "#28a745" if status == "active" else "#dc3545"
            rows += (
                f"<tr>"
                f"<td>{c.get('id')}</td>"
                f"<td>{c.get('hostname', '—')}</td>"
                f"<td>{c.get('ip_address', '—')}</td>"
                f"<td>{c.get('os_info', '—')[:40]}</td>"
                f"<td>{_fmt_ts(c.get('last_seen', ''))}</td>"
                f"<td style='color:{status_colour}'>{status}</td>"
                f"</tr>"
            )
        return f"""
<h2>💻 Client Status</h2>
<table>
  <thead>
    <tr><th>ID</th><th>Hostname</th><th>IP</th><th>OS</th>
        <th>Last Seen</th><th>Status</th></tr>
  </thead>
  <tbody>{rows or '<tr><td colspan="6">No clients registered</td></tr>'}</tbody>
</table>
"""

    @staticmethod
    def _section_recent_alerts(alerts: List[Dict[str, Any]]) -> str:
        rows = ""
        for a in alerts[:20]:
            rows += (
                f"<tr>"
                f"<td>{a.get('id')}</td>"
                f"<td>{_fmt_ts(a.get('timestamp', ''))}</td>"
                f"<td>{a.get('client_id')}</td>"
                f"<td>{a.get('rule_name', '—')}</td>"
                f"<td>{_badge(a.get('severity', 'LOW'))}</td>"
                f"<td>{(a.get('description') or '')[:80]}</td>"
                f"<td>{'✅' if a.get('acknowledged') else '⚠️'}</td>"
                f"</tr>"
            )
        return f"""
<h2>🚨 Recent Alerts</h2>
<table>
  <thead>
    <tr><th>ID</th><th>Time</th><th>Client</th><th>Rule</th>
        <th>Severity</th><th>Description</th><th>Ack</th></tr>
  </thead>
  <tbody>{rows or '<tr><td colspan="7">No alerts</td></tr>'}</tbody>
</table>
"""

    @staticmethod
    def _section_top_threats(alerts: List[Dict[str, Any]]) -> str:
        """Build a top-5 most frequent rule table."""
        counts: Dict[str, int] = {}
        for a in alerts:
            rule = a.get("rule_name", "unknown")
            counts[rule] = counts.get(rule, 0) + 1

        top5 = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]
        rows = "".join(
            f"<tr><td>{rule}</td><td>{cnt}</td></tr>"
            for rule, cnt in top5
        )
        return f"""
<h2>⚡ Top Threats</h2>
<table>
  <thead><tr><th>Rule / Threat</th><th>Count</th></tr></thead>
  <tbody>{rows or '<tr><td colspan="2">No threats detected</td></tr>'}</tbody>
</table>
"""

    @staticmethod
    def _section_recent_events(events: List[Dict[str, Any]]) -> str:
        rows = ""
        for e in events:
            rows += (
                f"<tr>"
                f"<td>{e.get('id')}</td>"
                f"<td>{_fmt_ts(e.get('timestamp', ''))}</td>"
                f"<td>{e.get('client_id')}</td>"
                f"<td>{e.get('event_type', '—')}</td>"
                f"<td>{_badge(e.get('severity', 'LOW'))}</td>"
                f"<td>{(e.get('description') or '')[:80]}</td>"
                f"</tr>"
            )
        return f"""
<h2>📋 Recent Events</h2>
<table>
  <thead>
    <tr><th>ID</th><th>Time</th><th>Client</th><th>Type</th>
        <th>Severity</th><th>Description</th></tr>
  </thead>
  <tbody>{rows or '<tr><td colspan="6">No events</td></tr>'}</tbody>
</table>
"""

    @staticmethod
    def _html_footer(generated_at: str) -> str:
        return f"""
<div class="footer">
  A-HIDS – AI-based Host Intrusion Detection System |
  Report generated at {generated_at}
</div>
</body>
</html>"""
