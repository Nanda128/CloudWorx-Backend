import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
    JWT_ACCESS_TOKEN_EXPIRES = 3600
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024


class LocalConfig(Config):
    """Configuration for local development with a local MySQL database."""

    SQLALCHEMY_DATABASE_URI = (
        os.environ.get("LOCAL_DATABASE_URL") or "mysql+pymysql://root:password@localhost/cloudworx_local"
    )
    FLASK_ENV = "development"
    FLASK_DEBUG = True
