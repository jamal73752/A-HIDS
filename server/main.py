"""
main.py - Entry point for the A-HIDS server.

Loads configuration, initialises the database, and starts the Flask API
on the configured host/port.  Handles startup errors gracefully.
"""

import logging
import os
import sys

import yaml

# Ensure project root is importable when run as a script
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from server.api import create_app  # noqa: E402

# ── Logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("ahids_server.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

CONFIG_PATH = os.path.join(_PROJECT_ROOT, "config", "config.yaml")


def load_config(path: str) -> dict:
    """
    Parse the YAML configuration file.

    Args:
        path: Path to config.yaml.

    Returns:
        Parsed configuration dict.

    Raises:
        SystemExit: On missing or malformed file.
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
        logger.critical("YAML parse error in %s: %s", path, exc)
        sys.exit(1)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    """Start the A-HIDS server."""
    logger.info("A-HIDS Server starting…")

    config = load_config(CONFIG_PATH)
    server_cfg = config.get("server", {})

    host = server_cfg.get("host", "0.0.0.0")
    port = int(server_cfg.get("port", 5000))
    debug = bool(server_cfg.get("debug", False))

    try:
        app = create_app(config)
        logger.info("Flask application created – listening on %s:%d", host, port)
        app.run(host=host, port=port, debug=debug, use_reloader=False)
    except OSError as exc:
        logger.critical("Could not bind to %s:%d – %s", host, port, exc)
        sys.exit(1)
    except Exception as exc:  # pylint: disable=broad-except
        logger.critical("Unexpected startup error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
