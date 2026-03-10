"""
process_monitor.py - Process monitoring module for A-HIDS client.

Lists all running processes, detects suspicious activity (high CPU/memory,
suspicious names), and tracks process creation/termination between snapshots.
Uses psutil for cross-platform compatibility.
"""

import logging
import time
from typing import Any, Dict, List, Set

import psutil

logger = logging.getLogger(__name__)

# ── Configuration constants ────────────────────────────────────────────────────

# CPU usage threshold (%) above which a process is flagged
HIGH_CPU_THRESHOLD = 80.0

# Memory usage threshold (MB) above which a process is flagged
HIGH_MEMORY_THRESHOLD_MB = 500.0

# Process names often associated with malicious activity
SUSPICIOUS_PROCESS_NAMES: Set[str] = {
    "nc", "ncat", "netcat", "nmap", "masscan", "hydra", "john",
    "hashcat", "mimikatz", "meterpreter", "metasploit", "sqlmap",
    "nikto", "wireshark", "tcpdump", "ettercap", "aircrack-ng",
    "reaver", "beef", "empire", "cobalt", "cobaltstrike",
    "psexec", "wce", "fgdump", "pwdump", "procdump",
    "cryptominer", "xmrig", "minerd", "cpuminer",
    # Windows-specific names often abused
    "powershell", "cmd", "wscript", "cscript", "mshta",
    "regsvr32", "rundll32", "certutil",
}


def _safe_get(proc: psutil.Process, attr: str, default: Any = None) -> Any:
    """Safely retrieve a process attribute, returning default on error."""
    try:
        return getattr(proc, attr)()
    except (psutil.NoSuchProcess, psutil.AccessDenied,
            psutil.ZombieProcess, AttributeError):
        return default


def _process_to_dict(proc: psutil.Process) -> Dict[str, Any]:
    """
    Convert a psutil.Process object to a serialisable dictionary.

    Args:
        proc: A psutil.Process instance.

    Returns:
        Dict with keys: pid, name, cpu_percent, memory_mb, memory_percent,
        user, status, create_time.
    """
    try:
        with proc.oneshot():
            cpu = _safe_get(proc, "cpu_percent", 0.0)
            mem_info = _safe_get(proc, "memory_info")
            mem_mb = (mem_info.rss / (1024 * 1024)) if mem_info else 0.0
            mem_pct = _safe_get(proc, "memory_percent", 0.0)
            create_ts = _safe_get(proc, "create_time", 0.0)

            return {
                "pid": proc.pid,
                "name": _safe_get(proc, "name", "unknown"),
                "cpu_percent": round(cpu, 2),
                "memory_mb": round(mem_mb, 2),
                "memory_percent": round(mem_pct or 0.0, 2),
                "user": _safe_get(proc, "username", "unknown"),
                "status": _safe_get(proc, "status", "unknown"),
                "create_time": create_ts,
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied,
            psutil.ZombieProcess):
        return {}


def _is_suspicious(proc_dict: Dict[str, Any]) -> bool:
    """
    Determine whether a process dict matches any suspicious criteria.

    A process is considered suspicious if:
      - Its CPU usage exceeds HIGH_CPU_THRESHOLD, OR
      - Its memory usage exceeds HIGH_MEMORY_THRESHOLD_MB, OR
      - Its name (lowercased) appears in SUSPICIOUS_PROCESS_NAMES.
    """
    if not proc_dict:
        return False

    name_lower = (proc_dict.get("name") or "").lower().split(".")[0]

    return (
        proc_dict.get("cpu_percent", 0) > HIGH_CPU_THRESHOLD
        or proc_dict.get("memory_mb", 0) > HIGH_MEMORY_THRESHOLD_MB
        or name_lower in SUSPICIOUS_PROCESS_NAMES
    )


class ProcessMonitor:
    """
    Cross-platform process monitor.

    Tracks all running processes, flags suspicious ones, and detects
    newly created or terminated processes between consecutive snapshots.
    """

    def __init__(self):
        """Initialise the monitor with an empty previous-snapshot."""
        # Maps PID -> process name from the previous collection cycle
        self._previous_pids: Dict[int, str] = {}
        # Small delay (seconds) between cpu_percent calls for accuracy
        self._cpu_interval: float = 0.1

    # ── Core collection ────────────────────────────────────────────────────────

    def get_all_processes(self) -> List[Dict[str, Any]]:
        """
        Enumerate all running processes on the host.

        Returns:
            List of process dicts (see _process_to_dict for keys).
            Empty dicts (failed reads) are excluded.
        """
        # First pass: trigger cpu_percent measurement
        procs = list(psutil.process_iter(["pid"]))
        for p in procs:
            try:
                p.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Allow the kernel time to gather the CPU delta
        time.sleep(self._cpu_interval)

        results = []
        for p in procs:
            d = _process_to_dict(p)
            if d:
                results.append(d)

        logger.debug("Collected %d process records", len(results))
        return results

    def get_suspicious_processes(
        self, process_list: List[Dict[str, Any]] | None = None
    ) -> List[Dict[str, Any]]:
        """
        Filter a process list to those flagged as suspicious.

        Args:
            process_list: Optional pre-collected list from get_all_processes().
                          If None, collects fresh data.

        Returns:
            List of suspicious process dicts.
        """
        procs = process_list if process_list is not None else self.get_all_processes()
        suspicious = [p for p in procs if _is_suspicious(p)]
        logger.debug("Detected %d suspicious processes", len(suspicious))
        return suspicious

    def get_process_changes(
        self, current_processes: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Compare current processes against the previous snapshot to identify
        newly created and recently terminated processes.

        Args:
            current_processes: Process list from the current cycle.

        Returns:
            Dict with keys ``new_processes`` and ``terminated_processes``,
            each containing a list of process dicts.
        """
        current_pids: Dict[int, str] = {
            p["pid"]: p.get("name", "unknown")
            for p in current_processes
            if p
        }

        new_pids = set(current_pids) - set(self._previous_pids)
        terminated_pids = set(self._previous_pids) - set(current_pids)

        new_procs = [p for p in current_processes if p.get("pid") in new_pids]
        terminated_procs = [
            {"pid": pid, "name": self._previous_pids[pid]}
            for pid in terminated_pids
        ]

        logger.debug(
            "Process changes – new: %d, terminated: %d",
            len(new_procs),
            len(terminated_procs),
        )

        # Update snapshot for next call
        self._previous_pids = current_pids

        return {
            "new_processes": new_procs,
            "terminated_processes": terminated_procs,
        }

    def collect(self) -> Dict[str, Any]:
        """
        Run a full collection cycle.

        Returns:
            Dict with keys:
              - ``all_processes``: complete process list
              - ``suspicious_processes``: filtered suspicious list
              - ``process_changes``: new/terminated processes since last call
              - ``total_count``: total number of running processes
              - ``suspicious_count``: count of suspicious processes
        """
        all_procs = self.get_all_processes()
        suspicious = self.get_suspicious_processes(all_procs)
        changes = self.get_process_changes(all_procs)

        return {
            "all_processes": all_procs,
            "suspicious_processes": suspicious,
            "process_changes": changes,
            "total_count": len(all_procs),
            "suspicious_count": len(suspicious),
        }


# Allow direct module execution for quick testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    monitor = ProcessMonitor()
    result = monitor.collect()
    print(f"Total processes : {result['total_count']}")
    print(f"Suspicious      : {result['suspicious_count']}")
    for sp in result["suspicious_processes"]:
        print(" ", sp)
