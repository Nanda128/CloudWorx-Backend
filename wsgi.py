import logging
import os
from logging.handlers import TimedRotatingFileHandler

from app import create_app

logger = logging.getLogger(__name__)

log_file = "app.log"
file_handler = TimedRotatingFileHandler(
    log_file,
    when="D",
    interval=7,
    backupCount=1,
    encoding="utf-8",
)
file_handler.setLevel(logging.INFO)

formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
file_handler.setFormatter(formatter)

logging.basicConfig(
    level=logging.INFO,
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
