"""
log_config.py - Structured logging configuration for A-HIDS server.

Sets up rotating file handlers for separate log streams (server, API,
security, AI) plus a colourised console handler for development.
"""

import logging
import logging.handlers
import os
import sys
from typing import Optional

# ── Colour codes for terminal output ──────────────────────────────────────────

_COLOURS = {
    "DEBUG": "\033[36m",    # Cyan
    "INFO": "\033[32m",     # Green
    "WARNING": "\033[33m",  # Yellow
    "ERROR": "\033[31m",    # Red
    "CRITICAL": "\033[35m", # Magenta
    "RESET": "\033[0m",
}


class ColouredFormatter(logging.Formatter):
    """Logging formatter that adds ANSI colour codes to the level name."""

    def format(self, record: logging.LogRecord) -> str:
        colour = _COLOURS.get(record.levelname, "")
        reset = _COLOURS["RESET"]
        record.levelname = f"{colour}{record.levelname}{reset}"
        return super().format(record)


# ── Log rotation settings ──────────────────────────────────────────────────────

_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
_BACKUP_COUNT = 5


def _rotating_handler(
    log_dir: str,
    filename: str,
    level: int = logging.DEBUG,
) -> logging.Handler:
    """
    Return a RotatingFileHandler for *filename* inside *log_dir*.

    Args:
        log_dir:  Directory for log files (created if absent).
        filename: Log file name (e.g. ``"server.log"``).
        level:    Minimum log level for this handler.

    Returns:
        Configured ``RotatingFileHandler``.
    """
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, filename)
    handler = logging.handlers.RotatingFileHandler(
        path,
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setLevel(level)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    return handler


def setup_logging(
    log_dir: str = "logs",
    console_level: int = logging.INFO,
    file_level: int = logging.DEBUG,
    use_colours: bool = True,
) -> None:
    """
    Configure structured logging for all A-HIDS server components.

    Creates four rotating log files:
      - ``logs/server.log``   – general server messages
      - ``logs/api.log``      – API request/response logs
      - ``logs/security.log`` – authentication and security events
      - ``logs/ai.log``       – AI engine predictions and training

    Also attaches a colourised (or plain) console handler to the root
    logger at *console_level*.

    Args:
        log_dir:       Directory for log files.
        console_level: Minimum level printed to stdout.
        file_level:    Minimum level written to log files.
        use_colours:   Attach colour formatting to the console handler.
    """
    root = logging.getLogger()
    # Avoid adding duplicate handlers when called multiple times
    if root.handlers:
        return

    root.setLevel(logging.DEBUG)

    # ── Console handler ────────────────────────────────────────────────────────
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    fmt = "%(asctime)s [%(levelname)s] %(name)s – %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    if use_colours and sys.stdout.isatty():
        console_handler.setFormatter(ColouredFormatter(fmt=fmt, datefmt=datefmt))
    else:
        console_handler.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
    root.addHandler(console_handler)

    # ── File handlers ──────────────────────────────────────────────────────────
    root.addHandler(_rotating_handler(log_dir, "server.log", file_level))

    # API logger
    api_logger = logging.getLogger("server.api")
    api_logger.addHandler(_rotating_handler(log_dir, "api.log", file_level))

    # Security logger
    security_logger = logging.getLogger("server.security")
    security_logger.addHandler(_rotating_handler(log_dir, "security.log", file_level))

    # AI logger
    ai_logger = logging.getLogger("server.ai_engine")
    ai_logger.addHandler(_rotating_handler(log_dir, "ai.log", file_level))

    logging.getLogger(__name__).info(
        "Logging configured – log_dir=%s console_level=%s",
        log_dir,
        logging.getLevelName(console_level),
    )
