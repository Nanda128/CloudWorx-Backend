import logging

from app import create_app

logger = logging.getLogger(__name__)

app = create_app()

if "tcp_server" in app.extensions and not app.extensions["tcp_server"].start():
    logger.warning("TCP server could not be started. Continuing without TCP server functionality.")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6175, debug=True)  # noqa: S104
