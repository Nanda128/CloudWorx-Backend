from __future__ import annotations

import os

from flask import Flask
from flask_cors import CORS
from flask_migrate import Migrate
from flask_restx import Api
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
migrate = Migrate()

api = Api(
    title="CloudWorx Backend API",
    version="1.0",
    description="API documentation for CloudWorx Backend",
    doc="/docs",
)


def create_app(config: object | None = None) -> Flask:
    app = Flask(__name__)

    if config:
        app.config.from_object(config)
    elif os.environ.get("USE_LOCAL_CONFIG", "0") == "1":
        from app.config import LocalConfig

        app.config.from_object(LocalConfig)
    else:
        app.config.from_object("app.config.Config")

    db.init_app(app)
    migrate.init_app(app, db)
    CORS(app)

    from app.routes.auth import auth_ns
    from app.routes.files import files_ns
    from app.routes.shares import shares_ns

    api.init_app(app)
    api.add_namespace(auth_ns, path="/api/auth")
    api.add_namespace(files_ns, path="/api/files")
    api.add_namespace(shares_ns, path="/api/shares")

    if app.config.get("ENABLE_TCP_SERVER", True):
        from app.tcp_server import SecureTCPServer

        if "extensions" not in app.__dict__:
            app.extensions = {}
        app.extensions["tcp_server"] = SecureTCPServer(
            app,
            host=app.config.get("TCP_HOST", "0.0.0.0"),  # noqa: S104
            port=app.config.get("TCP_PORT", 6174),
            cert_file=app.config.get("TLS_CERT_FILE", "server.crt"),
            key_file=app.config.get("TLS_KEY_FILE", "server.key"),
        )

    return app
