"""
websocket_manager.py - WebSocket real-time event broadcasting for A-HIDS.

Uses flask-socketio to push live events to the dashboard.
If flask-socketio is not installed the manager operates in no-op mode
so that the rest of the server continues to work.
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class WebSocketManager:
    """
    Wraps a Flask-SocketIO instance and exposes broadcast helpers.

    If flask-socketio is not installed every method is a silent no-op,
    preserving backward compatibility.

    Args:
        socketio: An initialised ``flask_socketio.SocketIO`` instance,
                  or None if WebSockets are disabled.
    """

    def __init__(self, socketio: Optional[Any] = None):
        self._sio = socketio
        self._enabled = socketio is not None
        if self._enabled:
            logger.info("WebSocket manager initialised (flask-socketio)")
        else:
            logger.info("WebSocket manager in no-op mode (flask-socketio not configured)")

    # ── Public API ─────────────────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        """True if a SocketIO instance is available."""
        return self._enabled

    def emit_new_alert(self, alert: Dict[str, Any]) -> None:
        """
        Broadcast a ``new_alert`` event to all connected dashboard clients.

        Args:
            alert: Alert dict (same format returned by database.get_alerts).
        """
        self._emit("new_alert", alert)

    def emit_client_status(self, client: Dict[str, Any], status: str) -> None:
        """
        Broadcast a ``client_status`` event.

        Args:
            client: Client dict.
            status: ``"connected"`` or ``"disconnected"``.
        """
        self._emit("client_status", {"client": client, "status": status})

    def emit_stats_update(self, stats: Dict[str, Any]) -> None:
        """
        Broadcast a ``stats_update`` event with aggregated statistics.

        Args:
            stats: Stats dict from ``DatabaseManager.get_stats()``.
        """
        self._emit("stats_update", stats)

    def emit_new_event(self, event: Dict[str, Any]) -> None:
        """
        Broadcast a ``new_event`` event to all connected clients.

        Args:
            event: Event dict.
        """
        self._emit("new_event", event)

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _emit(self, event_name: str, data: Any, room: Optional[str] = None) -> None:
        """Emit *event_name* with *data* via SocketIO, swallowing errors."""
        if not self._enabled:
            return
        try:
            if room:
                self._sio.emit(event_name, data, room=room)
            else:
                self._sio.emit(event_name, data)
            logger.debug("WebSocket event emitted: %s", event_name)
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("WebSocket emit error (%s): %s", event_name, exc)


def create_socketio(app: Any, cors_allowed_origins: str = "*") -> Optional[Any]:
    """
    Initialise a Flask-SocketIO instance attached to *app*.

    Returns None if flask-socketio is not installed.

    Args:
        app:                   Flask application instance.
        cors_allowed_origins:  CORS policy for WebSocket connections.

    Returns:
        Configured ``SocketIO`` instance or None.
    """
    try:
        from flask_socketio import SocketIO

        sio = SocketIO(
            app,
            cors_allowed_origins=cors_allowed_origins,
            async_mode="threading",
            logger=False,
            engineio_logger=False,
        )
        logger.info("Flask-SocketIO initialised")
        return sio
    except ImportError:
        logger.info(
            "flask-socketio not installed – WebSocket support disabled. "
            "Install it with: pip install flask-socketio"
        )
        return None
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("Failed to initialise Flask-SocketIO: %s", exc)
        return None
