"""
log_monitor.py - Log monitoring module for A-HIDS client.

Monitors Windows Event Log (Security, System, Application) for suspicious
activity including failed logins, privilege escalation attempts, and other
security-relevant events. Uses the pywin32 library (win32evtlog) on Windows.
"""

import logging
import os
import platform
import re
from datetime import datetime
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# ── Suspicious pattern definitions ────────────────────────────────────────────
SUSPICIOUS_PATTERNS = [
    {
        "name": "failed_login",
        "regex": re.compile(
            r"(Failed password|authentication failure|Invalid user|"
            r"FAILED LOGIN|failed login)",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
    },
    {
        "name": "sudo_usage",
        "regex": re.compile(r"\bsudo\b", re.IGNORECASE),
        "severity": "MEDIUM",
    },
    {
        "name": "privilege_escalation",
        "regex": re.compile(
            r"(su\[|sudo.*COMMAND|su:.*session opened for user root|"
            r"pam_unix.*session opened.*root)",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
    },
    {
        "name": "ssh_brute_force",
        "regex": re.compile(
            r"(Received disconnect|Connection closed by|"
            r"Too many authentication failures)",
            re.IGNORECASE,
        ),
        "severity": "MEDIUM",
    },
    {
        "name": "port_scan",
        "regex": re.compile(
            r"(port scan|SYN flood|possible scan)",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
    },
    {
        "name": "malware_indicator",
        "regex": re.compile(
            r"(malware|rootkit|trojan|exploit|shellcode)",
            re.IGNORECASE,
        ),
        "severity": "CRITICAL",
    },
    {
        "name": "account_manipulation",
        "regex": re.compile(
            r"(useradd|userdel|usermod|passwd|groupadd|groupdel)",
            re.IGNORECASE,
        ),
        "severity": "MEDIUM",
    },
]

# Timestamp formats commonly found in log files
TIMESTAMP_PATTERNS = [
    # syslog format: "Jan  1 12:00:00"
    re.compile(
        r"^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    ),
    # ISO 8601: "2024-01-01T12:00:00"
    re.compile(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    ),
    # Common date: "2024-01-01 12:00:00"
    re.compile(
        r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
    ),
]


def _parse_timestamp(line: str) -> str:
    """
    Extract and normalise a timestamp from a log line.

    Returns ISO-format string or current time if not parseable.
    """
    for pattern in TIMESTAMP_PATTERNS:
        match = pattern.match(line)
        if match:
            raw = match.group(1)
            # Try to parse syslog-style (no year)
            for fmt in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
                try:
                    parsed = datetime.strptime(raw, fmt)
                    # Use current year because syslog omits it
                    return parsed.replace(
                        year=datetime.now().year
                    ).isoformat()
                except ValueError:
                    pass
            # Try ISO / common formats
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.strptime(raw, fmt).isoformat()
                except ValueError:
                    pass
    return datetime.now().isoformat()


def _analyze_line(line: str, source: str) -> List[Dict[str, Any]]:
    """
    Check a single log line against all suspicious patterns.

    Returns a (possibly empty) list of event dicts.
    """
    events: List[Dict[str, Any]] = []
    timestamp = _parse_timestamp(line)

    for pattern_def in SUSPICIOUS_PATTERNS:
        if pattern_def["regex"].search(line):
            events.append(
                {
                    "timestamp": timestamp,
                    "source": source,
                    "message": line.strip(),
                    "severity": pattern_def["severity"],
                    "pattern_matched": pattern_def["name"],
                }
            )
            # One line can match multiple patterns – keep scanning
    return events


# ── Log file monitoring (for testing / non-Windows fallback) ──────────────────

def _read_log_file(filepath: str, max_lines: int = 500) -> List[Dict[str, Any]]:
    """
    Read the tail of a log file and return suspicious events.

    Args:
        filepath:  Absolute path to the log file.
        max_lines: Maximum number of lines to read from the file tail.

    Returns:
        List of event dicts matching suspicious patterns.
    """
    events: List[Dict[str, Any]] = []

    if not os.path.isfile(filepath):
        logger.debug("Log file not found (skipping): %s", filepath)
        return events

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()

        # Only analyse the most recent lines to avoid repeated alerts
        for line in lines[-max_lines:]:
            events.extend(_analyze_line(line, source=filepath))

    except PermissionError:
        logger.warning("Permission denied reading log file: %s", filepath)
    except OSError as exc:
        logger.error("OS error reading log file %s: %s", filepath, exc)

    return events


def _monitor_log_files(log_paths: List[str]) -> List[Dict[str, Any]]:
    """
    Monitor a list of log files.

    Args:
        log_paths: List of absolute file paths to monitor.

    Returns:
        Aggregated list of suspicious log events.
    """
    all_events: List[Dict[str, Any]] = []
    for path in log_paths:
        events = _read_log_file(path)
        logger.debug("Found %d events in %s", len(events), path)
        all_events.extend(events)
    return all_events


# ── Windows Event Log monitoring ──────────────────────────────────────────────

# Windows Event Log names to monitor
WINDOWS_EVENT_LOGS = ["Security", "System", "Application"]

# Security event IDs of interest mapped to (pattern_name, severity, description)
SECURITY_EVENT_IDS: Dict[int, tuple] = {
    4624: ("logon_success", "LOW", "An account was successfully logged on"),
    4625: ("failed_login", "HIGH", "An account failed to log on"),
    4634: ("logoff", "LOW", "An account was logged off"),
    4648: ("explicit_logon", "MEDIUM", "Logon using explicit credentials"),
    4657: ("registry_modified", "MEDIUM", "A registry value was modified"),
    4663: ("object_access", "LOW", "An attempt was made to access an object"),
    4688: ("process_created", "LOW", "A new process has been created"),
    4698: ("scheduled_task_created", "HIGH", "A scheduled task was created"),
    4699: ("scheduled_task_deleted", "HIGH", "A scheduled task was deleted"),
    4700: ("scheduled_task_enabled", "MEDIUM", "A scheduled task was enabled"),
    4701: ("scheduled_task_disabled", "MEDIUM", "A scheduled task was disabled"),
    4719: ("policy_change", "HIGH", "System audit policy was changed"),
    4720: ("account_created", "MEDIUM", "A user account was created"),
    4722: ("account_enabled", "MEDIUM", "A user account was enabled"),
    4723: ("password_change_attempt", "MEDIUM", "An attempt was made to change an account's password"),
    4724: ("password_reset", "HIGH", "An attempt was made to reset an account password"),
    4725: ("account_disabled", "MEDIUM", "A user account was disabled"),
    4726: ("account_deleted", "HIGH", "A user account was deleted"),
    4728: ("group_member_added", "MEDIUM", "A member was added to a security-enabled global group"),
    4732: ("local_group_member_added", "MEDIUM", "A member was added to a security-enabled local group"),
    4740: ("account_locked_out", "HIGH", "A user account was locked out"),
    4756: ("universal_group_member_added", "MEDIUM", "A member was added to a security-enabled universal group"),
    4776: ("credential_validation", "LOW", "The computer attempted to validate credentials"),
    7034: ("service_crashed", "HIGH", "A service terminated unexpectedly"),
    7036: ("service_status_changed", "LOW", "A service entered a status"),
    7040: ("service_start_type_changed", "MEDIUM", "The start type of a service was changed"),
    7045: ("new_service_installed", "HIGH", "A new service was installed in the system"),
}


def _monitor_windows_logs(log_names: List[str] | None = None) -> List[Dict[str, Any]]:
    """
    Read recent Windows Event Log entries from the specified logs.

    Args:
        log_names: List of Windows Event Log names to read
                   (defaults to WINDOWS_EVENT_LOGS).

    Returns:
        List of security-relevant event dicts.
    """
    events: List[Dict[str, Any]] = []
    logs_to_read = log_names or WINDOWS_EVENT_LOGS

    try:
        import win32evtlog  # type: ignore  # noqa: F401

        server = "localhost"

        for log_type in logs_to_read:
            try:
                hand = win32evtlog.OpenEventLog(server, log_type)
                flags = (
                    win32evtlog.EVENTLOG_BACKWARDS_READ
                    | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                )
                read_count = 0
                max_records = 200

                while read_count < max_records:
                    records = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not records:
                        break
                    for record in records:
                        if read_count >= max_records:
                            break
                        event_id = record.EventID & 0xFFFF
                        if event_id in SECURITY_EVENT_IDS:
                            pattern_name, severity, description = (
                                SECURITY_EVENT_IDS[event_id]
                            )
                            events.append(
                                {
                                    "timestamp": record.TimeGenerated.isoformat(),
                                    "source": f"Windows/{log_type}",
                                    "message": (
                                        f"EventID {event_id}: {description}"
                                    ),
                                    "severity": severity,
                                    "pattern_matched": pattern_name,
                                }
                            )
                        read_count += 1
                win32evtlog.CloseEventLog(hand)
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning(
                    "Could not read Windows %s log: %s", log_type, exc
                )

    except ImportError:
        logger.warning(
            "win32evtlog not available – Windows Event Log monitoring disabled. "
            "Install pywin32: pip install pywin32"
        )

    return events


# ── Public API ─────────────────────────────────────────────────────────────────

class LogMonitor:
    """
    Windows Event Log monitor for A-HIDS.

    Reads the Windows Security, System, and Application event logs via
    pywin32 and returns structured event records suitable for transmission
    to the A-HIDS server.

    On non-Windows platforms (or when log_paths is supplied), falls back to
    reading plain log files – this is intended for development and testing only.
    """

    def __init__(
        self,
        log_paths: List[str] | None = None,
        windows_logs: List[str] | None = None,
    ):
        """
        Initialise the monitor.

        Args:
            log_paths:    Override for plain log file paths. When provided on
                          any platform, file-based monitoring is used instead
                          of Windows Event Log. Primarily for testing.
            windows_logs: Windows Event Log names to read. Defaults to
                          ``["Security", "System", "Application"]``.
        """
        self._system = platform.system()
        self._log_paths = log_paths  # None means "use Windows Event Log"
        self._windows_logs = windows_logs or WINDOWS_EVENT_LOGS
        logger.debug(
            "LogMonitor initialised for %s; windows_logs=%s, file_paths=%s",
            self._system,
            self._windows_logs,
            self._log_paths,
        )

    def get_events(self) -> List[Dict[str, Any]]:
        """
        Collect suspicious log events from the host system.

        On Windows (and when log_paths is not set) reads from Windows Event
        Log.  When log_paths is provided, reads those files directly.

        Returns:
            List of event dicts, each with keys:
            ``timestamp``, ``source``, ``message``,
            ``severity``, ``pattern_matched``.
        """
        if self._log_paths is not None:
            # Explicit file paths supplied – use file-based monitoring
            # (supports testing on any platform)
            return _monitor_log_files(self._log_paths)

        # Primary mode: Windows Event Log
        return _monitor_windows_logs(self._windows_logs)


# Allow direct module execution for quick testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    monitor = LogMonitor()
    found = monitor.get_events()
    print(f"Found {len(found)} suspicious log events")
    for evt in found[:10]:
        print(evt)
