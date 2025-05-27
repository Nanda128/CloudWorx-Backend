import datetime  # noqa: INP001
import logging
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import current_app

from app.models.file import File
from app.models.user import UserLogin

logger = logging.getLogger(__name__)


def authenticate_user(message: dict[str, Any]) -> dict[str, Any]:
    """Authenticate a user from a message"""
    username = message.get("username")
    password = message.get("password")

    if not username or not password:
        return {"status": "error", "message": "Missing username or password"}

    user = UserLogin.query.filter_by(username=username).first()
    if not user:
        return {"status": "error", "message": "User not found"}

    try:
        PasswordHasher().verify(user.auth_password, password)
    except VerifyMismatchError:
        return {"status": "error", "message": "Invalid password"}

    jwt_secret = current_app.config["JWT_SECRET_KEY"]
    if not jwt_secret:
        return {"status": "error", "message": "JWT secret key is not set in environment variables"}

    token = jwt.encode(
        {
            "user_id": user.id,
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        },
        jwt_secret,
        algorithm="HS256",
    )

    return {
        "status": "success",
        "message": "Authentication successful",
        "token": token,
        "user_id": user.id,
    }


def list_files(user_id: str) -> dict[str, Any]:
    """List files for a user"""
    files = File.query.filter_by(created_by=user_id).all()
    files_data = [
        {
            "file_id": file.file_id,
            "file_name": file.file_name,
            "file_type": file.file_type,
            "file_size": file.file_size,
        }
        for file in files
    ]

    return {
        "status": "success",
        "files": files_data,
        "count": len(files_data),
    }


def validate_token(token: str) -> str:
    """Validate JWT token and return user_id"""
    try:
        jwt_secret = current_app.config["JWT_SECRET_KEY"]
        data = jwt.decode(token, jwt_secret, algorithms=["HS256"])
        user_id = data.get("user_id")

        user = UserLogin.query.filter_by(id=user_id).first()
        if not user:
            error_message = "User not found"
            raise ValueError(error_message)
    except jwt.ExpiredSignatureError as err:
        error_message = "Token has expired"
        raise ValueError(error_message) from err
    except jwt.InvalidTokenError as err:
        error_message = "Invalid token"
        raise ValueError(error_message) from err
    else:
        return user_id


def handle_message(message: dict[str, Any]) -> dict[str, Any]:
    """Handle a message based on its command"""
    result = None
    try:
        command = message.get("command")
        if not command:
            result = {"status": "error", "message": "No command specified"}
        elif command == "login":
            result = authenticate_user(message)
        else:
            token = message.get("token")
            if not token:
                result = {"status": "error", "message": "Authentication token required"}
            else:
                try:
                    user_id = validate_token(token)
                    if command == "list_files":
                        result = list_files(user_id)
                    elif command in {"download_file", "upload_file"}:
                        result = {"status": "error", "message": "Not implemented yet"}
                    else:
                        result = {"status": "error", "message": f"Unknown command: {command}"}
                except ValueError as e:
                    result = {"status": "error", "message": str(e)}
    except Exception as e:
        logger.exception("Error handling message")
        result = {"status": "error", "message": f"Internal error: {e!s}"}
    return result
