"""
app.py - Flask application factory for the A-HIDS dashboard.

Creates the Flask app with correct template and static directories,
registers the routes blueprint, and configures CORS.
"""

import logging
import os
import sys

import yaml
from flask import Flask
from flask_cors import CORS

# Ensure project root is importable when run as a script
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

logger = logging.getLogger(__name__)

CONFIG_PATH = os.path.join(_PROJECT_ROOT, "config", "config.yaml")


def _load_config(path: str) -> dict:
    """Load YAML config, returning an empty dict on any error."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except (FileNotFoundError, yaml.YAMLError) as exc:
        logger.warning("Could not load config from %s: %s", path, exc)
        return {}


def create_app(config: dict | None = None) -> Flask:
    """
    Create and configure the A-HIDS dashboard Flask application.

    Args:
        config: Optional configuration dict (overrides config.yaml).

    Returns:
        Configured Flask app instance.
    """
    # Resolve template and static directories relative to this file
    _here = os.path.dirname(os.path.abspath(__file__))
    template_folder = os.path.join(_here, "templates")
    static_folder = os.path.join(_here, "static")

    app = Flask(
        __name__,
        template_folder=template_folder,
        static_folder=static_folder,
    )

    # Load configuration
    cfg = config or _load_config(CONFIG_PATH)
    dashboard_cfg = cfg.get("dashboard", {})
    server_cfg = cfg.get("server", {})

    app.config["SECRET_KEY"] = os.urandom(32).hex()
    app.config["SERVER_API_URL"] = (
        f"http://{server_cfg.get('host', 'localhost')}:"
        f"{server_cfg.get('port', 5000)}"
    )
    app.config["AUTH_TOKEN"] = cfg.get("client", {}).get(
        "auth_token", "your-secret-token"
    )
    app.config["AHIDS_CONFIG"] = cfg

    # Enable CORS for API interactions from dashboard
    CORS(app)

    # Register routes blueprint
    from dashboard.routes import dashboard_bp  # noqa: E402 (avoid circular import)
    app.register_blueprint(dashboard_bp)

    logger.info(
        "Dashboard app created – template: %s, static: %s",
        template_folder,
        static_folder,
    )
    return app


def main():
    """
    Start the A-HIDS dashboard web server.

    Reads host/port from config.yaml ``dashboard`` section.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    )

    cfg = _load_config(CONFIG_PATH)
    dashboard_cfg = cfg.get("dashboard", {})
    host = dashboard_cfg.get("host", "0.0.0.0")
    port = int(dashboard_cfg.get("port", 8080))

    app = create_app(cfg)
    logger.info("A-HIDS Dashboard starting on %s:%d", host, port)
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
