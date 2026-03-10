"""
network_monitor.py - Network connection monitoring module for A-HIDS client.

Monitors active TCP/UDP connections and listening ports using psutil.
Detects connections to suspicious ports or unusual external IPs and returns
structured data suitable for transmission to the A-HIDS server.
"""

import logging
import socket
from datetime import datetime
from typing import Any, Dict, List, Set

import psutil

logger = logging.getLogger(__name__)

# ── Suspicious port definitions ────────────────────────────────────────────────

# Ports commonly used by malware, backdoors, and C2 frameworks
SUSPICIOUS_PORTS: Set[int] = {
    4444,   # Metasploit default
    6666,   # IRC / malware
    1337,   # "leet" backdoor
    31337,  # "elite" backdoor
    8888,   # Various malware / Jupyter exposed
    9999,   # Various backdoors
    12345,  # NetBus
    12346,  # NetBus
    27374,  # Sub7
    65535,  # Common high port backdoor
    6667,   # IRC (often used for botnets)
    6697,   # IRC over TLS
    3389,   # RDP – flag unusual outbound
    5900,   # VNC
    5901,   # VNC
    23,     # Telnet (unencrypted)
    512,    # rexec
    513,    # rlogin
    514,    # rsh
    2222,   # Alternate SSH (can be legit, still flag)
    4899,   # Radmin
    1080,   # SOCKS proxy
    9050,   # Tor
    9051,   # Tor control
}

# Private/loopback address prefixes – connections to these are generally
# considered internal and less suspicious
PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.", "127.", "::1", "fc",
                    "fd")


def _is_external_ip(ip: str) -> bool:
    """Return True if *ip* is a globally routable (non-private) address."""
    if not ip:
        return False
    for prefix in PRIVATE_PREFIXES:
        if ip.startswith(prefix):
            return False
    return True


def _get_process_name(pid: int | None) -> str:
    """Safely resolve a PID to a process name."""
    if pid is None:
        return "unknown"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
        return "unknown"


def _conn_to_dict(conn) -> Dict[str, Any]:
    """
    Convert a psutil connection object to a serialisable dict.

    Args:
        conn: A psutil connection named-tuple.

    Returns:
        Dict with connection details.
    """
    laddr = conn.laddr
    raddr = conn.raddr

    local_ip = laddr.ip if laddr else ""
    local_port = laddr.port if laddr else 0
    remote_ip = raddr.ip if raddr else ""
    remote_port = raddr.port if raddr else 0

    return {
        "local_addr": local_ip,
        "local_port": local_port,
        "remote_addr": remote_ip,
        "remote_port": remote_port,
        "protocol": "tcp" if conn.type == socket.SOCK_STREAM else "udp",
        "status": conn.status,
        "pid": conn.pid,
        "process_name": _get_process_name(conn.pid),
        "timestamp": datetime.now().isoformat(),
    }


def _is_suspicious_conn(conn_dict: Dict[str, Any]) -> bool:
    """
    Evaluate whether a connection dict should be flagged as suspicious.

    Criteria:
      - Remote port is in SUSPICIOUS_PORTS, OR
      - Local port is in SUSPICIOUS_PORTS, OR
      - Remote IP is external AND remote port is in SUSPICIOUS_PORTS
    """
    remote_port = conn_dict.get("remote_port", 0)
    local_port = conn_dict.get("local_port", 0)

    if remote_port in SUSPICIOUS_PORTS:
        return True
    if local_port in SUSPICIOUS_PORTS:
        return True

    # Flag outbound connections on unusual high ports to external IPs
    remote_ip = conn_dict.get("remote_addr", "")
    if _is_external_ip(remote_ip) and remote_port and remote_port > 49151:
        # Ephemeral-range outbound to external – lower-confidence flag
        # Only flag if the process name itself is suspicious
        proc = conn_dict.get("process_name", "").lower()
        if any(s in proc for s in ("nc", "ncat", "python", "perl", "ruby",
                                    "bash", "sh", "powershell", "cmd")):
            return True

    return False


def _get_listening_ports() -> List[Dict[str, Any]]:
    """
    Return a list of all ports currently in LISTEN state.

    Returns:
        List of dicts with keys: port, protocol, pid, process_name.
    """
    listening: List[Dict[str, Any]] = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == psutil.CONN_LISTEN:
                listening.append(
                    {
                        "port": conn.laddr.port if conn.laddr else 0,
                        "protocol": (
                            "tcp" if conn.type == socket.SOCK_STREAM else "udp"
                        ),
                        "pid": conn.pid,
                        "process_name": _get_process_name(conn.pid),
                    }
                )
    except (psutil.AccessDenied, OSError) as exc:
        logger.warning("Could not enumerate listening ports: %s", exc)

    return listening


def _get_network_stats() -> Dict[str, Any]:
    """
    Return overall network interface statistics.

    Returns:
        Dict with bytes_sent, bytes_recv, packets_sent, packets_recv,
        errin, errout, dropin, dropout.
    """
    try:
        counters = psutil.net_io_counters()
        return {
            "bytes_sent": counters.bytes_sent,
            "bytes_recv": counters.bytes_recv,
            "packets_sent": counters.packets_sent,
            "packets_recv": counters.packets_recv,
            "errin": counters.errin,
            "errout": counters.errout,
            "dropin": counters.dropin,
            "dropout": counters.dropout,
        }
    except (psutil.AccessDenied, OSError) as exc:
        logger.warning("Could not read net IO counters: %s", exc)
        return {}


class NetworkMonitor:
    """
    Network connection and port monitor.

    Collects all active network connections, identifies suspicious ones,
    lists listening ports, and gathers interface-level I/O statistics.
    """

    def collect(self) -> Dict[str, Any]:
        """
        Run a full network collection cycle.

        Returns:
            Dict with keys:
              - ``all_connections``:      list of all active connections
              - ``suspicious_connections``: connections matching suspicious criteria
              - ``listening_ports``:       ports in LISTEN state
              - ``stats``:                 interface I/O counters
              - ``total_connections``:     total connection count
              - ``suspicious_count``:      suspicious connection count
              - ``timestamp``:             ISO timestamp of this collection
        """
        all_conns: List[Dict[str, Any]] = []
        suspicious_conns: List[Dict[str, Any]] = []

        try:
            raw_connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied as exc:
            logger.warning(
                "Access denied enumerating connections: %s", exc
            )
            raw_connections = []
        except OSError as exc:
            logger.error("OS error enumerating connections: %s", exc)
            raw_connections = []

        for conn in raw_connections:
            try:
                d = _conn_to_dict(conn)
                all_conns.append(d)
                if _is_suspicious_conn(d):
                    suspicious_conns.append(d)
                    logger.warning(
                        "Suspicious connection: %s:%s -> %s:%s (pid=%s)",
                        d["local_addr"],
                        d["local_port"],
                        d["remote_addr"],
                        d["remote_port"],
                        d["pid"],
                    )
            except Exception as exc:  # pylint: disable=broad-except
                logger.debug("Error processing connection: %s", exc)

        listening = _get_listening_ports()
        stats = _get_network_stats()

        logger.debug(
            "Network: %d connections, %d suspicious, %d listening",
            len(all_conns),
            len(suspicious_conns),
            len(listening),
        )

        return {
            "all_connections": all_conns,
            "suspicious_connections": suspicious_conns,
            "listening_ports": listening,
            "stats": stats,
            "total_connections": len(all_conns),
            "suspicious_count": len(suspicious_conns),
            "timestamp": datetime.now().isoformat(),
        }


# Allow direct module execution for quick testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    monitor = NetworkMonitor()
    result = monitor.collect()
    print(f"Connections : {result['total_connections']}")
    print(f"Suspicious  : {result['suspicious_count']}")
    print(f"Listening   : {len(result['listening_ports'])}")
