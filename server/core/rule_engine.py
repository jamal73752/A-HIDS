"""
rule_engine.py - Deterministic rule evaluation engine for A-HIDS server.

Evaluates incoming collected-data payloads against a set of predefined
security rules.  Returns a list of matched rule dicts that the AlertManager
can act upon.
"""

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# ── Predefined rules ──────────────────────────────────────────────────────────
#
# Each rule is a dict with keys:
#   name        – unique machine-readable identifier
#   description – human-readable explanation
#   severity    – LOW | MEDIUM | HIGH | CRITICAL
#   enabled     – bool (can be toggled at runtime)
#
# The ``_evaluate`` method below contains the matching logic for each rule.
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_RULES: List[Dict[str, Any]] = [
    {
        "name": "brute_force_ssh",
        "description": (
            "Multiple failed SSH login attempts detected – "
            "possible brute-force attack"
        ),
        "severity": "HIGH",
        "enabled": True,
    },
    {
        "name": "unauthorized_file_modification",
        "description": (
            "Critical system file has been modified, added, or deleted"
        ),
        "severity": "CRITICAL",
        "enabled": True,
    },
    {
        "name": "suspicious_process",
        "description": (
            "A process matching known-malicious names or exhibiting "
            "abnormal resource usage was detected"
        ),
        "severity": "HIGH",
        "enabled": True,
    },
    {
        "name": "unusual_network_traffic",
        "description": (
            "One or more connections to suspicious ports or unusual "
            "external hosts were detected"
        ),
        "severity": "HIGH",
        "enabled": True,
    },
    {
        "name": "privilege_escalation",
        "description": (
            "A privilege escalation event (sudo/su) was recorded in system logs"
        ),
        "severity": "HIGH",
        "enabled": True,
    },
    {
        "name": "high_cpu_usage",
        "description": "CPU utilisation exceeded 90 % – possible crypto-mining",
        "severity": "MEDIUM",
        "enabled": True,
    },
    {
        "name": "high_memory_usage",
        "description": "Memory utilisation exceeded 90 %",
        "severity": "MEDIUM",
        "enabled": True,
    },
    {
        "name": "new_listening_port",
        "description": "A new port is listening that was not present previously",
        "severity": "MEDIUM",
        "enabled": True,
    },
    {
        "name": "account_manipulation",
        "description": "User/group account creation or modification detected in logs",
        "severity": "HIGH",
        "enabled": True,
    },
]

# Failed-login threshold for brute-force rule
BRUTE_FORCE_THRESHOLD = 5

# CPU / memory thresholds for resource-usage rules
HIGH_CPU_THRESHOLD = 90.0
HIGH_MEM_THRESHOLD = 90.0

# Privilege-escalation pattern keywords
PRIVESC_PATTERNS = frozenset(
    ["privilege_escalation", "sudo_usage"]
)

# Account-manipulation pattern keywords
ACCOUNT_PATTERNS = frozenset(["account_manipulation"])


class RuleEngine:
    """
    Evaluates a collected-data payload against all configured detection rules.

    Rules are stored as an in-memory list and can be toggled at runtime.

    Args:
        custom_rules: Optional list of rule dicts to replace the defaults.
    """

    def __init__(self, custom_rules: List[Dict[str, Any]] | None = None):
        self._rules: List[Dict[str, Any]] = custom_rules or [
            dict(r) for r in DEFAULT_RULES
        ]
        logger.debug("RuleEngine loaded %d rules", len(self._rules))

    # ── Public API ─────────────────────────────────────────────────────────────

    def evaluate(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Test a payload against all enabled rules.

        Args:
            data: Collected-data dict from DataCollector.collect().

        Returns:
            List of matched rule dicts, each augmented with an
            ``evidence`` key describing the triggering data.
        """
        matches: List[Dict[str, Any]] = []

        for rule in self._rules:
            if not rule.get("enabled", True):
                continue

            try:
                result = self._evaluate_rule(rule["name"], data)
                if result is not None:
                    matched = dict(rule)
                    matched["evidence"] = result
                    matches.append(matched)
                    logger.info(
                        "Rule matched: %s (severity=%s)",
                        rule["name"],
                        rule["severity"],
                    )
            except Exception as exc:  # pylint: disable=broad-except
                logger.error(
                    "Error evaluating rule %s: %s", rule["name"], exc
                )

        logger.debug(
            "%d/%d rules matched", len(matches), len(self._rules)
        )
        return matches

    def toggle_rule(self, name: str, enabled: bool) -> bool:
        """
        Enable or disable a rule by name.

        Args:
            name:    Rule name to toggle.
            enabled: New enabled state.

        Returns:
            True if a rule with that name was found.
        """
        for rule in self._rules:
            if rule["name"] == name:
                rule["enabled"] = enabled
                logger.info("Rule %s set enabled=%s", name, enabled)
                return True
        logger.warning("Rule not found: %s", name)
        return False

    def get_rules(self) -> List[Dict[str, Any]]:
        """Return a copy of all configured rules."""
        return [dict(r) for r in self._rules]

    # ── Per-rule evaluation logic ──────────────────────────────────────────────

    def _evaluate_rule(
        self, name: str, data: Dict[str, Any]
    ) -> Dict[str, Any] | None:
        """
        Dispatch to the correct evaluation function for a given rule name.

        Returns:
            Evidence dict if the rule matches, else None.
        """
        if name == "brute_force_ssh":
            return self._check_brute_force(data)
        if name == "unauthorized_file_modification":
            return self._check_file_modification(data)
        if name == "suspicious_process":
            return self._check_suspicious_process(data)
        if name == "unusual_network_traffic":
            return self._check_network_traffic(data)
        if name == "privilege_escalation":
            return self._check_privilege_escalation(data)
        if name == "high_cpu_usage":
            return self._check_high_cpu(data)
        if name == "high_memory_usage":
            return self._check_high_memory(data)
        if name == "new_listening_port":
            return self._check_listening_ports(data)
        if name == "account_manipulation":
            return self._check_account_manipulation(data)
        logger.debug("No evaluator for rule: %s", name)
        return None

    # ── Individual rule implementations ───────────────────────────────────────

    @staticmethod
    def _check_brute_force(data: Dict[str, Any]) -> Dict[str, Any] | None:
        """Trigger if failed login events exceed the threshold."""
        log_events = data.get("log_events", [])
        failed = [
            e for e in log_events
            if isinstance(e, dict)
            and e.get("pattern_matched") == "failed_login"
        ]
        if len(failed) >= BRUTE_FORCE_THRESHOLD:
            return {
                "failed_login_count": len(failed),
                "threshold": BRUTE_FORCE_THRESHOLD,
                "sample_events": failed[:3],
            }
        return None

    @staticmethod
    def _check_file_modification(data: Dict[str, Any]) -> Dict[str, Any] | None:
        """Trigger if any critical file was modified, added, or deleted."""
        fi = data.get("file_integrity", {})
        modified = fi.get("modified", [])
        added = fi.get("added", [])
        deleted = fi.get("deleted", [])
        total = len(modified) + len(added) + len(deleted)
        if total > 0:
            return {
                "modified": modified,
                "added": added,
                "deleted": deleted,
                "total_changes": total,
            }
        return None

    @staticmethod
    def _check_suspicious_process(data: Dict[str, Any]) -> Dict[str, Any] | None:
        """Trigger if any suspicious process was detected."""
        susp = data.get("suspicious_processes", [])
        if susp:
            return {
                "suspicious_process_count": len(susp),
                "processes": [
                    {"pid": p.get("pid"), "name": p.get("name"),
                     "cpu": p.get("cpu_percent"), "mem_mb": p.get("memory_mb")}
                    for p in susp[:5]
                ],
            }
        return None

    @staticmethod
    def _check_network_traffic(data: Dict[str, Any]) -> Dict[str, Any] | None:
        """Trigger if any connection was classified as suspicious."""
        network = data.get("network", {})
        susp_conns = network.get("suspicious_connections", [])
        if susp_conns:
            return {
                "suspicious_connection_count": len(susp_conns),
                "connections": susp_conns[:5],
            }
        return None

    @staticmethod
    def _check_privilege_escalation(data: Dict[str, Any]) -> Dict[str, Any] | None:
        """Trigger if log events contain privilege-escalation patterns."""
        log_events = data.get("log_events", [])
        privesc = [
            e for e in log_events
            if isinstance(e, dict)
            and e.get("pattern_matched") in PRIVESC_PATTERNS
        ]
        if privesc:
            return {
                "event_count": len(privesc),
                "events": privesc[:3],
            }
        return None

    @staticmethod
    def _check_high_cpu(data: Dict[str, Any]) -> Dict[str, Any] | None:
        """Trigger if overall CPU usage exceeds the threshold."""
        sys_info = data.get("system_info", {})
        cpu = (
            data.get("cpu_usage")
            or sys_info.get("cpu_usage")
            or (sys_info.get("cpu") or {}).get("overall_percent", 0)
            or 0
        )
        if float(cpu) > HIGH_CPU_THRESHOLD:
            return {"cpu_usage": float(cpu), "threshold": HIGH_CPU_THRESHOLD}
        return None

    @staticmethod
    def _check_high_memory(data: Dict[str, Any]) -> Dict[str, Any] | None:
        """Trigger if memory usage exceeds the threshold."""
        sys_info = data.get("system_info", {})
        mem = (
            data.get("memory_usage")
            or sys_info.get("memory_usage")
            or (sys_info.get("memory") or {}).get("percent", 0)
            or 0
        )
        if float(mem) > HIGH_MEM_THRESHOLD:
            return {"memory_usage": float(mem), "threshold": HIGH_MEM_THRESHOLD}
        return None

    @staticmethod
    def _check_listening_ports(data: Dict[str, Any]) -> Dict[str, Any] | None:
        """
        Trigger if any listening port falls in the suspicious range.

        Note: full delta tracking would require persistent state between
        calls; here we flag ports from the suspicious list as a signal.
        """
        from client.network_monitor import SUSPICIOUS_PORTS  # lazy import

        network = data.get("network", {})
        listening = network.get("listening_ports", [])
        flagged = [
            p for p in listening
            if isinstance(p, dict) and p.get("port", 0) in SUSPICIOUS_PORTS
        ]
        if flagged:
            return {"flagged_ports": flagged}
        return None

    @staticmethod
    def _check_account_manipulation(data: Dict[str, Any]) -> Dict[str, Any] | None:
        """Trigger if account creation/modification was logged."""
        log_events = data.get("log_events", [])
        account_events = [
            e for e in log_events
            if isinstance(e, dict)
            and e.get("pattern_matched") in ACCOUNT_PATTERNS
        ]
        if account_events:
            return {
                "event_count": len(account_events),
                "events": account_events[:3],
            }
        return None
