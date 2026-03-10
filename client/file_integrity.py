"""
file_integrity.py - File integrity monitoring module for A-HIDS client.

Computes SHA-256 hashes for critical system files, stores a baseline in
baseline.json, and detects modifications, additions, and deletions between
successive checks.
"""

import hashlib
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Default path for the baseline hash store
DEFAULT_BASELINE_PATH = "baseline.json"

# Default critical files to monitor
DEFAULT_MONITORED_PATHS: List[str] = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/crontab",
]


def _sha256(filepath: str) -> str | None:
    """
    Compute the SHA-256 hash of a file.

    Args:
        filepath: Absolute path to the file.

    Returns:
        Hexadecimal SHA-256 digest string, or ``None`` if the file
        cannot be read.
    """
    sha = hashlib.sha256()
    try:
        with open(filepath, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                sha.update(chunk)
        return sha.hexdigest()
    except PermissionError:
        logger.warning("Permission denied reading file: %s", filepath)
    except OSError as exc:
        logger.error("OS error hashing %s: %s", filepath, exc)
    return None


def _load_baseline(baseline_path: str) -> Dict[str, Any]:
    """
    Load the stored baseline from a JSON file.

    Args:
        baseline_path: Path to the baseline JSON file.

    Returns:
        Dict mapping file paths to their stored metadata, or an empty
        dict if the file does not exist or cannot be parsed.
    """
    if not os.path.isfile(baseline_path):
        logger.debug("No baseline file found at %s – starting fresh", baseline_path)
        return {}
    try:
        with open(baseline_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Could not load baseline %s: %s", baseline_path, exc)
        return {}


def _save_baseline(baseline: Dict[str, Any], baseline_path: str) -> None:
    """
    Persist the current baseline to a JSON file.

    Args:
        baseline:      Dict mapping file paths to their hash metadata.
        baseline_path: Destination path for the JSON file.
    """
    try:
        with open(baseline_path, "w", encoding="utf-8") as fh:
            json.dump(baseline, fh, indent=2)
        logger.debug("Baseline saved to %s", baseline_path)
    except OSError as exc:
        logger.error("Could not save baseline to %s: %s", baseline_path, exc)


class FileIntegrityMonitor:
    """
    File integrity monitor using SHA-256 hashes.

    On first run (no baseline file) a baseline is created from the
    current state of the monitored files.  On subsequent runs, the
    current hashes are compared against the baseline and any
    modifications, additions, or deletions are reported.
    """

    def __init__(
        self,
        monitored_paths: List[str] | None = None,
        baseline_path: str = DEFAULT_BASELINE_PATH,
    ):
        """
        Initialise the monitor.

        Args:
            monitored_paths: List of file/directory paths to watch.
                             Defaults to DEFAULT_MONITORED_PATHS.
            baseline_path:   Path to the JSON file used to persist hashes.
        """
        self._paths: List[str] = monitored_paths or DEFAULT_MONITORED_PATHS
        self._baseline_path: str = baseline_path
        logger.debug(
            "FileIntegrityMonitor watching %d paths; baseline at %s",
            len(self._paths),
            self._baseline_path,
        )

    # ── Baseline management ────────────────────────────────────────────────────

    def create_baseline(self) -> Dict[str, Any]:
        """
        Hash all monitored files and save the result as the new baseline.

        Returns:
            The newly created baseline dict.
        """
        baseline: Dict[str, Any] = {}
        for path in self._paths:
            if os.path.isfile(path):
                digest = _sha256(path)
                if digest:
                    baseline[path] = {
                        "hash": digest,
                        "size": os.path.getsize(path),
                        "last_modified": os.path.getmtime(path),
                        "baseline_created": datetime.now().isoformat(),
                    }
                    logger.debug("Baselined %s → %s", path, digest[:16])
            else:
                logger.debug("Path not found during baseline creation: %s", path)

        _save_baseline(baseline, self._baseline_path)
        logger.info(
            "Baseline created/updated with %d file(s)", len(baseline)
        )
        return baseline

    # ── Integrity check ────────────────────────────────────────────────────────

    def check_integrity(self) -> Dict[str, Any]:
        """
        Compare current file hashes against the stored baseline.

        If no baseline exists, one is created and an empty result is
        returned (first run is always clean).

        Returns:
            Dict with keys:
              - ``modified``:  list of files whose hash changed.
              - ``added``:     list of new files not in the baseline.
              - ``deleted``:   list of baseline files that no longer exist.
              - ``unchanged``: list of files whose hash matches the baseline.
              - ``total_monitored``: total number of monitored paths.
              - ``check_time``: ISO timestamp of this check.
        """
        baseline = _load_baseline(self._baseline_path)

        # First run – create baseline and report everything clean
        if not baseline:
            logger.info("No baseline found – creating initial baseline")
            self.create_baseline()
            return {
                "modified": [],
                "added": [],
                "deleted": [],
                "unchanged": list(self._paths),
                "total_monitored": len(self._paths),
                "check_time": datetime.now().isoformat(),
            }

        modified: List[Dict[str, Any]] = []
        added: List[Dict[str, Any]] = []
        unchanged: List[str] = []

        # Check each monitored path
        for path in self._paths:
            if os.path.isfile(path):
                current_hash = _sha256(path)
                if current_hash is None:
                    continue  # Could not read; skip

                if path not in baseline:
                    # File is new since the baseline was taken
                    added.append(
                        {
                            "path": path,
                            "current_hash": current_hash,
                            "size": os.path.getsize(path),
                            "detected_at": datetime.now().isoformat(),
                        }
                    )
                    logger.warning("New file detected (not in baseline): %s", path)
                elif current_hash != baseline[path]["hash"]:
                    # File exists but hash differs
                    modified.append(
                        {
                            "path": path,
                            "old_hash": baseline[path]["hash"],
                            "new_hash": current_hash,
                            "size": os.path.getsize(path),
                            "detected_at": datetime.now().isoformat(),
                        }
                    )
                    logger.warning("File modification detected: %s", path)
                else:
                    unchanged.append(path)
            elif path in baseline:
                # Was in baseline but no longer present
                logger.warning("File deleted (was in baseline): %s", path)
                # Deletion is collected separately below

        # Identify deletions: paths in baseline that are no longer present
        current_existing = {
            p for p in self._paths if os.path.isfile(p)
        }
        deleted = [
            {
                "path": path,
                "last_known_hash": info["hash"],
                "detected_at": datetime.now().isoformat(),
            }
            for path, info in baseline.items()
            if path not in current_existing
        ]

        result = {
            "modified": modified,
            "added": added,
            "deleted": deleted,
            "unchanged": unchanged,
            "total_monitored": len(self._paths),
            "check_time": datetime.now().isoformat(),
        }

        if modified or added or deleted:
            logger.warning(
                "Integrity issues – modified: %d, added: %d, deleted: %d",
                len(modified),
                len(added),
                len(deleted),
            )
        else:
            logger.debug("All monitored files are unchanged")

        return result

    def update_baseline_for_path(self, path: str) -> bool:
        """
        Update the baseline entry for a single file (e.g. after a
        legitimate change).

        Args:
            path: Absolute file path to re-baseline.

        Returns:
            True if updated successfully, False otherwise.
        """
        if not os.path.isfile(path):
            logger.error("Cannot update baseline – file not found: %s", path)
            return False

        digest = _sha256(path)
        if digest is None:
            return False

        baseline = _load_baseline(self._baseline_path)
        baseline[path] = {
            "hash": digest,
            "size": os.path.getsize(path),
            "last_modified": os.path.getmtime(path),
            "baseline_created": datetime.now().isoformat(),
        }
        _save_baseline(baseline, self._baseline_path)
        logger.info("Baseline updated for %s", path)
        return True


# Allow direct module execution for quick testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    monitor = FileIntegrityMonitor()
    result = monitor.check_integrity()
    print("Modified:", result["modified"])
    print("Added   :", result["added"])
    print("Deleted :", result["deleted"])
