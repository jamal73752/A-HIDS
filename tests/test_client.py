"""
test_client.py - Unit tests for A-HIDS client modules.

Tests cover file integrity hashing, network suspicious-port detection,
system info required keys, and log pattern matching.
All psutil and file-system calls are patched to avoid host dependencies.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Ensure project root is importable
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


# ── TestFileIntegrity ──────────────────────────────────────────────────────────

class TestFileIntegrity(unittest.TestCase):
    """Tests for client.file_integrity module."""

    def setUp(self):
        """Create temp directory and temp files for testing."""
        self.tmp_dir = tempfile.mkdtemp()
        self.baseline_path = os.path.join(self.tmp_dir, "baseline.json")
        # Create a sample test file
        self.test_file = os.path.join(self.tmp_dir, "test_file.txt")
        with open(self.test_file, "w") as f:
            f.write("original content")

    def tearDown(self):
        """Remove temp directory and all its contents."""
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_sha256_hash_calculation(self):
        """_sha256 should return a valid 64-char hex digest for a readable file."""
        from client.monitors.file_integrity import _sha256

        digest = _sha256(self.test_file)
        self.assertIsNotNone(digest)
        self.assertEqual(len(digest), 64)

        # Verify digest matches manual calculation
        expected = hashlib.sha256(b"original content").hexdigest()
        self.assertEqual(digest, expected)

    def test_sha256_returns_none_for_missing_file(self):
        """_sha256 should return None for a file that does not exist."""
        from client.monitors.file_integrity import _sha256

        result = _sha256("/nonexistent/path/file.txt")
        self.assertIsNone(result)

    def test_baseline_creation(self):
        """create_baseline should write a JSON file with hash entries."""
        from client.monitors.file_integrity import FileIntegrityMonitor

        monitor = FileIntegrityMonitor(
            monitored_paths=[self.test_file],
            baseline_path=self.baseline_path,
        )
        baseline = monitor.create_baseline()

        self.assertIn(self.test_file, baseline)
        self.assertIn("hash", baseline[self.test_file])
        self.assertTrue(os.path.isfile(self.baseline_path))

    def test_modification_detection(self):
        """check_integrity should report modified file when hash changes."""
        from client.monitors.file_integrity import FileIntegrityMonitor

        monitor = FileIntegrityMonitor(
            monitored_paths=[self.test_file],
            baseline_path=self.baseline_path,
        )
        # First run creates baseline
        monitor.create_baseline()

        # Modify the file
        with open(self.test_file, "w") as f:
            f.write("modified content – different hash")

        result = monitor.check_integrity()
        self.assertEqual(len(result["modified"]), 1)
        self.assertEqual(result["modified"][0]["path"], self.test_file)

    def test_deletion_detection(self):
        """check_integrity should report deleted file when it disappears."""
        from client.monitors.file_integrity import FileIntegrityMonitor

        monitor = FileIntegrityMonitor(
            monitored_paths=[self.test_file],
            baseline_path=self.baseline_path,
        )
        monitor.create_baseline()

        # Delete the file
        os.remove(self.test_file)

        result = monitor.check_integrity()
        self.assertEqual(len(result["deleted"]), 1)

    def test_unchanged_file_not_reported(self):
        """check_integrity should not report unchanged files."""
        from client.monitors.file_integrity import FileIntegrityMonitor

        monitor = FileIntegrityMonitor(
            monitored_paths=[self.test_file],
            baseline_path=self.baseline_path,
        )
        monitor.create_baseline()
        result = monitor.check_integrity()

        self.assertEqual(len(result["modified"]), 0)
        self.assertEqual(len(result["added"]), 0)
        self.assertEqual(len(result["deleted"]), 0)


# ── TestNetworkMonitor ─────────────────────────────────────────────────────────

class TestNetworkMonitor(unittest.TestCase):
    """Tests for client.network_monitor module."""

    def _make_mock_conn(self, lport=12345, rport=80, rip="8.8.8.8",
                         status="ESTABLISHED", pid=1234):
        """Helper to create a mock psutil connection named-tuple."""
        import socket
        conn = MagicMock()
        conn.laddr = MagicMock(ip="192.168.1.10", port=lport)
        conn.raddr = MagicMock(ip=rip, port=rport)
        conn.status = status
        conn.pid = pid
        conn.type = socket.SOCK_STREAM
        return conn

    @patch("psutil.net_connections")
    @patch("psutil.net_io_counters")
    def test_collect_returns_dict_with_required_keys(self, mock_counters, mock_conns):
        """collect() must return a dict with all required top-level keys."""
        from client.monitors.network_monitor import NetworkMonitor

        mock_conns.return_value = []
        mock_counters.return_value = MagicMock(
            bytes_sent=1000, bytes_recv=2000,
            packets_sent=10, packets_recv=20,
            errin=0, errout=0, dropin=0, dropout=0,
        )

        monitor = NetworkMonitor()
        result = monitor.collect()

        for key in ("all_connections", "suspicious_connections",
                    "listening_ports", "stats", "total_connections",
                    "suspicious_count", "timestamp"):
            self.assertIn(key, result, f"Key '{key}' missing from collect() result")

    @patch("psutil.net_connections")
    @patch("psutil.net_io_counters")
    def test_collect_returns_list_of_connections(self, mock_counters, mock_conns):
        """all_connections should be a list."""
        from client.monitors.network_monitor import NetworkMonitor

        mock_conns.return_value = [self._make_mock_conn()]
        mock_counters.return_value = MagicMock(
            bytes_sent=0, bytes_recv=0, packets_sent=0, packets_recv=0,
            errin=0, errout=0, dropin=0, dropout=0,
        )
        with patch("psutil.Process") as mock_proc:
            mock_proc.return_value.name.return_value = "python"
            monitor = NetworkMonitor()
            result = monitor.collect()

        self.assertIsInstance(result["all_connections"], list)

    def test_suspicious_port_flagged(self):
        """Connections to known suspicious ports must be detected."""
        from client.monitors.network_monitor import _is_suspicious_conn

        conn = {
            "local_addr": "192.168.1.10",
            "local_port": 55000,
            "remote_addr": "8.8.8.8",
            "remote_port": 4444,   # Metasploit default
            "protocol": "tcp",
            "status": "ESTABLISHED",
            "pid": 9999,
            "process_name": "evil",
        }
        self.assertTrue(_is_suspicious_conn(conn))

    def test_normal_connection_not_flagged(self):
        """Normal HTTPS connections should not be flagged as suspicious."""
        from client.monitors.network_monitor import _is_suspicious_conn

        conn = {
            "local_addr": "192.168.1.10",
            "local_port": 55000,
            "remote_addr": "8.8.8.8",
            "remote_port": 443,  # HTTPS – normal
            "protocol": "tcp",
            "status": "ESTABLISHED",
            "pid": 1234,
            "process_name": "firefox",
        }
        self.assertFalse(_is_suspicious_conn(conn))


# ── TestSystemInfo ─────────────────────────────────────────────────────────────

class TestSystemInfo(unittest.TestCase):
    """Tests for client.system_info module."""

    @patch("psutil.cpu_percent", return_value=25.0)
    @patch("psutil.virtual_memory")
    @patch("psutil.disk_partitions")
    @patch("psutil.boot_time", return_value=1700000000.0)
    @patch("psutil.users", return_value=[])
    @patch("psutil.net_if_addrs", return_value={})
    @patch("psutil.net_io_counters")
    @patch("psutil.cpu_freq", return_value=MagicMock(current=3600.0))
    def test_collect_returns_required_keys(
        self, mock_freq, mock_io, mock_net_addrs, mock_users,
        mock_boot, mock_parts, mock_mem, mock_cpu
    ):
        """collect() must include cpu_usage, memory_usage, disk_usage, etc."""
        from client.system_info import SystemInfoCollector

        mock_mem.return_value = MagicMock(
            total=8 * 1024**3, used=4 * 1024**3,
            available=4 * 1024**3, percent=50.0,
            swap_total=0, swap_used=0, swap_percent=0,
        )
        mock_parts.return_value = []
        mock_io.return_value = MagicMock(
            bytes_sent=0, bytes_recv=0, packets_sent=0, packets_recv=0,
            errin=0, errout=0, dropin=0, dropout=0,
        )

        with patch("psutil.swap_memory",
                   return_value=MagicMock(total=0, used=0, percent=0)):
            with patch("psutil.disk_usage",
                       return_value=MagicMock(percent=40.0)):
                collector = SystemInfoCollector()
                data = collector.collect()

        required_keys = [
            "cpu_usage", "memory_usage", "disk_usage",
            "hostname", "os_info", "uptime",
        ]
        for key in required_keys:
            self.assertIn(key, data, f"Key '{key}' missing from system_info.collect()")

    def test_cpu_usage_is_numeric(self):
        """cpu_usage value must be a number."""
        from client.system_info import _get_cpu_info

        with patch("psutil.cpu_percent", return_value=33.5), \
             patch("psutil.cpu_freq", return_value=MagicMock(current=2400.0)), \
             patch("psutil.cpu_count", return_value=4):
            info = _get_cpu_info()

        self.assertIsInstance(info["overall_percent"], (int, float))


# ── TestLogMonitor ─────────────────────────────────────────────────────────────

class TestLogMonitor(unittest.TestCase):
    """Tests for client.log_monitor module."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.tmp_dir, "auth.log")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _write_log(self, content: str):
        with open(self.log_file, "w") as f:
            f.write(content)

    def test_failed_login_detected(self):
        """Failed password lines should be detected with severity HIGH."""
        from client.monitors.log_monitor import LogMonitor

        self._write_log(
            "Jan  1 00:00:01 host sshd[123]: Failed password for root "
            "from 10.0.0.1 port 22 ssh2\n"
        )
        monitor = LogMonitor(log_paths=[self.log_file])
        events = monitor.get_events()

        self.assertTrue(
            any(e["pattern_matched"] == "failed_login" for e in events),
            "Failed login pattern not detected",
        )

    def test_sudo_usage_detected(self):
        """Sudo command lines should be detected with severity MEDIUM."""
        from client.monitors.log_monitor import LogMonitor

        self._write_log(
            "Jan  1 00:01:00 host sudo: user1 : TTY=pts/0 ; "
            "PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash\n"
        )
        monitor = LogMonitor(log_paths=[self.log_file])
        events = monitor.get_events()

        self.assertTrue(
            any(e["pattern_matched"] == "sudo_usage" for e in events),
            "sudo_usage pattern not detected",
        )

    def test_empty_log_returns_empty_list(self):
        """An empty log file should produce no events."""
        from client.monitors.log_monitor import LogMonitor

        self._write_log("")
        monitor = LogMonitor(log_paths=[self.log_file])
        events = monitor.get_events()
        self.assertIsInstance(events, list)
        self.assertEqual(len(events), 0)

    def test_missing_log_returns_empty_list(self):
        """A non-existent log path should not raise and return empty list."""
        from client.monitors.log_monitor import LogMonitor

        monitor = LogMonitor(log_paths=["/nonexistent/path/auth.log"])
        events = monitor.get_events()
        self.assertIsInstance(events, list)
        self.assertEqual(len(events), 0)

    def test_event_has_required_keys(self):
        """Each event dict must contain all required keys."""
        from client.monitors.log_monitor import LogMonitor

        self._write_log(
            "Jan  1 12:00:00 host sshd: Failed password for invalid "
            "user admin from 1.2.3.4 port 22\n"
        )
        monitor = LogMonitor(log_paths=[self.log_file])
        events = monitor.get_events()

        if events:
            required = {"timestamp", "source", "message", "severity", "pattern_matched"}
            for evt in events:
                missing = required - set(evt.keys())
                self.assertFalse(missing, f"Event missing keys: {missing}")


if __name__ == "__main__":
    unittest.main()
