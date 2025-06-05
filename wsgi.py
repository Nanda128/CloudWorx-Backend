import logging
import os
from logging.handlers import TimedRotatingFileHandler

from app import create_app

logger = logging.getLogger(__name__)

log_file = os.environ.get("LOG_FILE", "app.log")
log_level = getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper())
log_rotation_days = int(os.environ.get("LOG_ROTATION_DAYS", "7"))

file_handler = TimedRotatingFileHandler(
    log_file,
    when="D",
    interval=log_rotation_days,
    backupCount=1,
    encoding="utf-8",
)
file_handler.setLevel(log_level)

formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
file_handler.setFormatter(formatter)

logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        file_handler,
        logging.StreamHandler(),
    ],
)

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "6174"))
    host = os.environ.get("HOST", "127.0.0.1")
    debug = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1", "t")

    logger.info("Starting Flask application on %s:%s (debug=%s)", host, port, debug)
    try:
        app.run(host=host, port=port, debug=debug)
    except Exception:
        logger.exception("Failed to start Flask application")
        raise
