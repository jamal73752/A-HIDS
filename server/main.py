"""
main.py - Entry point for the A-HIDS server.

Loads configuration, initialises the database, and starts the Flask API
on the configured host/port.  Handles startup errors gracefully.

Phase 1 additions:
  - Structured logging via log_config.setup_logging()
  - SSL/TLS support with auto-generated self-signed certs
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

# Bootstrap logging early; log_config will reconfigure with full handlers.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
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

    # ── Set up structured logging ──────────────────────────────────────────
    try:
        from server.infra.log_config import setup_logging
        log_dir = server_cfg.get("log_dir", "logs")
        setup_logging(log_dir=log_dir)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("Could not set up structured logging: %s", exc)

    host = server_cfg.get("host", "0.0.0.0")
    port = int(server_cfg.get("port", 5000))
    debug = bool(server_cfg.get("debug", False))

    # ── SSL context ────────────────────────────────────────────────────────
    ssl_context = None
    ssl_enabled = bool(server_cfg.get("ssl_enabled", False))
    if ssl_enabled:
        try:
            from server.infra.ssl_manager import get_ssl_context
            cert_path = server_cfg.get("ssl_cert", "certs/server.crt")
            key_path = server_cfg.get("ssl_key", "certs/server.key")
            ssl_context = get_ssl_context(ssl_enabled, cert_path, key_path)
            if ssl_context:
                logger.info("HTTPS enabled – cert=%s key=%s", cert_path, key_path)
            else:
                logger.warning("SSL requested but context could not be created – using HTTP")
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("SSL setup failed (%s) – falling back to HTTP", exc)

    try:
        app = create_app(config)
        scheme = "https" if ssl_context else "http"
        logger.info(
            "Flask application created – listening on %s://%s:%d",
            scheme, host, port,
        )
        app.run(
            host=host,
            port=port,
            debug=debug,
            use_reloader=False,
            ssl_context=ssl_context,
        )
    except OSError as exc:
        logger.critical("Could not bind to %s:%d – %s", host, port, exc)
        sys.exit(1)
    except Exception as exc:  # pylint: disable=broad-except
        logger.critical("Unexpected startup error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
