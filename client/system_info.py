"""
system_info.py - System information collector for A-HIDS client.

Gathers CPU, RAM, disk, uptime, OS details, hostname, IP addresses,
and logged-in users using psutil and standard library modules.
"""

import logging
import platform
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

import psutil

logger = logging.getLogger(__name__)


def _get_cpu_info() -> Dict[str, Any]:
    """
    Collect CPU usage statistics.

    Returns:
        Dict with overall (percent) and per-core CPU usage, plus
        logical and physical core counts.
    """
    # Interval=1 gives a non-zero measurement on the first call
    overall = psutil.cpu_percent(interval=1)
    per_core = psutil.cpu_percent(interval=None, percpu=True)
    freq = psutil.cpu_freq()

    return {
        "overall_percent": overall,
        "per_core_percent": per_core,
        "logical_cores": psutil.cpu_count(logical=True),
        "physical_cores": psutil.cpu_count(logical=False),
        "frequency_mhz": round(freq.current, 2) if freq else None,
    }


def _get_memory_info() -> Dict[str, Any]:
    """
    Collect RAM statistics.

    Returns:
        Dict with total, used, available (bytes and percent).
    """
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()

    return {
        "total_bytes": mem.total,
        "used_bytes": mem.used,
        "available_bytes": mem.available,
        "percent": mem.percent,
        "total_mb": round(mem.total / (1024 ** 2), 2),
        "used_mb": round(mem.used / (1024 ** 2), 2),
        "available_mb": round(mem.available / (1024 ** 2), 2),
        "swap_total_mb": round(swap.total / (1024 ** 2), 2),
        "swap_used_mb": round(swap.used / (1024 ** 2), 2),
        "swap_percent": swap.percent,
    }


def _get_disk_info() -> List[Dict[str, Any]]:
    """
    Collect disk usage for every mounted partition.

    Returns:
        List of dicts per partition with device, mountpoint, fstype,
        total/used/free (bytes) and percent used.
    """
    partitions: List[Dict[str, Any]] = []

    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            partitions.append(
                {
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "free_bytes": usage.free,
                    "percent": usage.percent,
                    "total_gb": round(usage.total / (1024 ** 3), 2),
                    "used_gb": round(usage.used / (1024 ** 3), 2),
                    "free_gb": round(usage.free / (1024 ** 3), 2),
                }
            )
        except (PermissionError, OSError) as exc:
            logger.debug(
                "Could not read disk usage for %s: %s",
                part.mountpoint,
                exc,
            )

    return partitions


def _get_uptime() -> Dict[str, Any]:
    """
    Calculate system uptime from psutil boot time.

    Returns:
        Dict with boot_time (ISO string), uptime_seconds, and a
        human-readable uptime_str.
    """
    boot_ts = psutil.boot_time()
    boot_dt = datetime.fromtimestamp(boot_ts, tz=timezone.utc)
    uptime_secs = time.time() - boot_ts

    days = int(uptime_secs // 86400)
    hours = int((uptime_secs % 86400) // 3600)
    minutes = int((uptime_secs % 3600) // 60)

    return {
        "boot_time": boot_dt.isoformat(),
        "uptime_seconds": int(uptime_secs),
        "uptime_str": f"{days}d {hours}h {minutes}m",
    }


def _get_os_info() -> Dict[str, Any]:
    """
    Gather operating system information using the platform module.

    Returns:
        Dict with system, node, release, version, machine, processor.
    """
    uname = platform.uname()
    return {
        "system": uname.system,
        "node": uname.node,
        "release": uname.release,
        "version": uname.version,
        "machine": uname.machine,
        "processor": uname.processor,
        "python_version": platform.python_version(),
    }


def _get_network_identity() -> Dict[str, Any]:
    """
    Resolve the host's hostname and reachable IP addresses.

    Returns:
        Dict with hostname and a list of IP address strings.
    """
    hostname = socket.gethostname()
    ip_addresses: List[str] = []

    # Gather all addresses from all interfaces via psutil
    try:
        for _iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family in (socket.AF_INET, socket.AF_INET6):
                    ip_addresses.append(addr.address)
    except OSError as exc:
        logger.warning("Could not enumerate network interfaces: %s", exc)

    # Fallback: use socket resolution
    if not ip_addresses:
        try:
            ip_addresses = [socket.gethostbyname(hostname)]
        except socket.gaierror:
            ip_addresses = ["127.0.0.1"]

    return {"hostname": hostname, "ip_addresses": ip_addresses}


def _get_logged_in_users() -> List[Dict[str, Any]]:
    """
    Return a list of currently logged-in users from psutil.users().

    Returns:
        List of dicts with name, terminal, host, started, pid fields.
    """
    users: List[Dict[str, Any]] = []
    try:
        for u in psutil.users():
            started_dt = datetime.fromtimestamp(
                u.started, tz=timezone.utc
            ).isoformat()
            users.append(
                {
                    "name": u.name,
                    "terminal": u.terminal or "",
                    "host": u.host or "",
                    "started": started_dt,
                    "pid": u.pid,
                }
            )
    except OSError as exc:
        logger.warning("Could not enumerate logged-in users: %s", exc)

    return users


class SystemInfoCollector:
    """
    Comprehensive host system information collector.

    Aggregates CPU, memory, disk, uptime, OS, network identity, and
    logged-in user data into a single structured dictionary.
    """

    def collect(self) -> Dict[str, Any]:
        """
        Gather all system information.

        Returns:
            Dict with keys: timestamp, cpu, memory, disks, uptime,
            os_info, network, users, hostname, ip_address (primary).
        """
        net_id = _get_network_identity()
        primary_ip = next(
            (ip for ip in net_id["ip_addresses"] if not ip.startswith("127")),
            "127.0.0.1",
        )

        info = {
            "timestamp": datetime.now().isoformat(),
            "hostname": net_id["hostname"],
            "ip_address": primary_ip,
            "cpu": _get_cpu_info(),
            "memory": _get_memory_info(),
            "disks": _get_disk_info(),
            "uptime": _get_uptime(),
            "os_info": _get_os_info(),
            "network": net_id,
            "users": _get_logged_in_users(),
            # Convenience top-level fields used by AI feature extraction
            "cpu_usage": psutil.cpu_percent(interval=None),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_usage": (
                psutil.disk_usage("/").percent
                if platform.system() != "Windows"
                else psutil.disk_usage("C:\\").percent
            ),
        }

        logger.debug(
            "SystemInfo collected – CPU %.1f%%, MEM %.1f%%, DISK %.1f%%",
            info["cpu_usage"],
            info["memory_usage"],
            info["disk_usage"],
        )
        return info


# Allow direct module execution for quick testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    collector = SystemInfoCollector()
    data = collector.collect()
    import json
    print(json.dumps(data, indent=2, default=str))
