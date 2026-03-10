"""
main.py - Entry point for the A-HIDS client agent.

Loads configuration, initialises all monitoring modules, and runs the
main collection-and-send loop at the configured interval.
Supports graceful shutdown on SIGINT (Ctrl-C) and, on POSIX systems,
SIGTERM. Windows does not support SIGTERM, so only SIGINT is registered
there.
"""

import logging
import os
import signal
import sys
import time
from typing import Any, Dict

import yaml

# Ensure the project root is on sys.path when run directly
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from client.data_collector import DataCollector  # noqa: E402
from client.sender import Sender                 # noqa: E402

# ── Logging setup ──────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("ahids_client.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

CONFIG_PATH = os.path.join(_PROJECT_ROOT, "config", "config.yaml")


def load_config(path: str) -> Dict[str, Any]:
    """
    Load and parse the YAML configuration file.

    Args:
        path: Absolute or relative path to config.yaml.

    Returns:
        Parsed configuration as a nested dict.

    Raises:
        SystemExit: If the file cannot be found or parsed.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        logger.info("Configuration loaded from %s", path)
        return cfg
    except FileNotFoundError:
        logger.critical("Configuration file not found: %s", path)
        sys.exit(1)
    except yaml.YAMLError as exc:
        logger.critical("Failed to parse configuration: %s", exc)
        sys.exit(1)


# ── Graceful shutdown ─────────────────────────────────────────────────────────

_running = True


def _shutdown_handler(signum, _frame):
    """Handle SIGINT / SIGTERM by setting the loop exit flag."""
    global _running  # pylint: disable=global-statement
    logger.info("Shutdown signal received (%s) – stopping…", signum)
    _running = False


# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    """
    Start the A-HIDS client agent.

    Loads config, initialises modules, and loops until interrupted.
    """
    global _running  # pylint: disable=global-statement

    # Register signal handlers for graceful shutdown.
    # SIGTERM is not available on Windows, so only register it on POSIX systems.
    signal.signal(signal.SIGINT, _shutdown_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _shutdown_handler)

    config = load_config(CONFIG_PATH)
    client_cfg: Dict[str, Any] = config.get("client", {})

    interval: int = int(client_cfg.get("collection_interval", 30))
    logger.info(
        "A-HIDS client starting – interval: %ds, server: %s",
        interval,
        client_cfg.get("server_url", "http://localhost:5000"),
    )

    collector = DataCollector(client_cfg)
    sender = Sender(client_cfg)

    # Optional: verify server connectivity before entering the loop
    if sender.ping():
        logger.info("Server is reachable – beginning collection loop")
    else:
        logger.warning(
            "Server not reachable at startup – will retry on each cycle"
        )

    cycle = 0
    while _running:
        cycle += 1
        logger.info("─── Collection cycle %d ───", cycle)

        try:
            payload = collector.collect()
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Collection cycle failed: %s", exc, exc_info=True)
            payload = None

        if payload:
            success = sender.send(payload)
            if success:
                logger.info("Cycle %d: data delivered successfully", cycle)
            else:
                logger.warning(
                    "Cycle %d: failed to deliver data to server", cycle
                )

        if _running:
            logger.debug("Sleeping %ds until next cycle…", interval)
            # Sleep in short increments so shutdown signals are processed quickly
            for _ in range(interval * 10):
                if not _running:
                    break
                time.sleep(0.1)

    logger.info("A-HIDS client stopped after %d collection cycle(s)", cycle)


if __name__ == "__main__":
    main()
