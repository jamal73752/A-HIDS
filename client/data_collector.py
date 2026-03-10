"""
data_collector.py - Aggregates all monitor module outputs for A-HIDS.

The DataCollector class orchestrates all client-side monitoring modules
and bundles their results into a single structured payload ready for
transmission to the A-HIDS server.
"""

import logging
import socket
from datetime import datetime
from typing import Any, Dict

from client.monitors.file_integrity import FileIntegrityMonitor
from client.monitors.log_monitor import LogMonitor
from client.monitors.network_monitor import NetworkMonitor
from client.monitors.process_monitor import ProcessMonitor
from client.system_info import SystemInfoCollector

logger = logging.getLogger(__name__)


class DataCollector:
    """
    Orchestrates all A-HIDS monitoring modules.

    Each call to :meth:`collect` gathers a complete snapshot of the
    host's security-relevant state and returns it as a structured dict.

    Args:
        config: The ``client`` section of config.yaml as a Python dict.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialise all sub-monitors from the supplied configuration.

        Args:
            config: Dict containing at minimum ``monitored_paths`` and
                    ``monitored_logs`` keys.
        """
        self._config = config
        monitored_paths = config.get("monitored_paths", [])
        monitored_logs = config.get("monitored_logs", [])

        self._system_info = SystemInfoCollector()
        self._process_monitor = ProcessMonitor()
        self._log_monitor = LogMonitor(log_paths=monitored_logs)
        self._network_monitor = NetworkMonitor()
        self._file_monitor = FileIntegrityMonitor(
            monitored_paths=monitored_paths
        )

        logger.info(
            "DataCollector initialised – paths: %d, logs: %d",
            len(monitored_paths),
            len(monitored_logs),
        )

    # ── Private helpers ────────────────────────────────────────────────────────

    def _safe_collect(self, name: str, fn):
        """
        Execute a collection function and return its result.

        On any exception the error is logged and an empty dict/list is
        returned so that a single failing module does not break the
        entire collection cycle.

        Args:
            name: Human-readable module name (for logging).
            fn:   Zero-argument callable to invoke.

        Returns:
            The callable's return value, or {} / [] on error.
        """
        try:
            return fn()
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Error in %s collector: %s", name, exc, exc_info=True)
            return {}

    # ── Public API ─────────────────────────────────────────────────────────────

    def collect(self) -> Dict[str, Any]:
        """
        Run a full collection cycle across all monitoring modules.

        Returns:
            Dict with the following keys:
              - ``timestamp``            – ISO-format collection time
              - ``hostname``             – host FQDN or short name
              - ``system_info``          – CPU, memory, disk, OS details
              - ``processes``            – all running processes list
              - ``suspicious_processes`` – processes flagged as suspicious
              - ``process_changes``      – new / terminated since last run
              - ``log_events``           – suspicious log entries detected
              - ``network``              – connections, ports, and stats
              - ``file_integrity``       – modified / added / deleted files
        """
        logger.debug("Starting full collection cycle")
        timestamp = datetime.now().isoformat()
        hostname = socket.gethostname()

        # ── System information ─────────────────────────────────────────────
        sys_info = self._safe_collect("system_info", self._system_info.collect)

        # ── Processes ─────────────────────────────────────────────────────
        proc_data = self._safe_collect("process_monitor", self._process_monitor.collect)
        all_procs = proc_data.get("all_processes", [])
        suspicious_procs = proc_data.get("suspicious_processes", [])
        proc_changes = proc_data.get("process_changes", {})

        # ── Log events ────────────────────────────────────────────────────
        log_events = self._safe_collect("log_monitor", self._log_monitor.get_events)
        if not isinstance(log_events, list):
            log_events = []

        # ── Network ───────────────────────────────────────────────────────
        network = self._safe_collect("network_monitor", self._network_monitor.collect)

        # ── File integrity ────────────────────────────────────────────────
        file_integrity = self._safe_collect(
            "file_integrity", self._file_monitor.check_integrity
        )

        payload = {
            "timestamp": timestamp,
            "hostname": hostname,
            "system_info": sys_info,
            "processes": all_procs,
            "suspicious_processes": suspicious_procs,
            "process_changes": proc_changes,
            "log_events": log_events,
            "network": network,
            "file_integrity": file_integrity,
        }

        logger.info(
            "Collection complete – procs: %d, suspicious: %d, "
            "log_events: %d, net_suspicious: %d",
            len(all_procs),
            len(suspicious_procs),
            len(log_events),
            network.get("suspicious_count", 0),
        )

        return payload
