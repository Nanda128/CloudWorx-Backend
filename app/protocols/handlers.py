from __future__ import annotations  # noqa: INP001

import base64
import binascii
import datetime
import logging
import uuid
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import current_app
from werkzeug.utils import secure_filename

from app import db
from app.models.file import File, FileDEK
from app.models.share import FileShare
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


def list_shared_files(user_id: str) -> dict[str, Any]:
    """List files shared with a user"""
    shares = FileShare.query.filter_by(shared_with=user_id).all()
    files_data = []

    for share in shares:
        file = File.query.filter_by(file_id=share.file_id).first()
        if not file:
            continue

        files_data.append(
            {
                "file_id": file.file_id,
                "file_name": file.file_name,
                "file_type": file.file_type,
                "file_size": file.file_size,
                "created_at": file.created_at.isoformat() if file.created_at else None,
            },
        )

    return {
        "status": "success",
        "files": files_data,
        "count": len(files_data),
    }


def list_file_shares(user_id: str, file_id: str) -> dict[str, Any]:
    """List users a file is shared with"""
    file = File.query.filter_by(file_id=file_id, created_by=user_id).first()
    if not file:
        return {"status": "error", "message": "File not found or access denied"}

    shares = FileShare.query.filter_by(file_id=file.file_id).all()

    shares_data = [
        {
            "share_id": s.share_id,
            "shared_with": s.shared_with,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in shares
    ]

    return {
        "status": "success",
        "shares": shares_data,
        "count": len(shares_data),
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


def download_file(user_id: str, file_id: str) -> dict[str, Any]:
    """Download a file by ID"""
    file = File.query.filter_by(file_id=file_id).first()
    if not file:
        return {"status": "error", "message": "File not found"}

    is_owner = file.created_by == user_id
    if not is_owner:
        share = FileShare.query.filter_by(file_id=file_id, shared_with=user_id).first()
        if not share:
            return {"status": "error", "message": "Access denied"}

    dek = FileDEK.query.filter_by(file_id=file.file_id).first()
    if not dek:
        return {"status": "error", "message": "File encryption key not found"}

    return {
        "status": "success",
        "file_data": {
            "file_id": file.file_id,
            "file_name": file.file_name,
            "file_type": file.file_type,
            "file_size": file.file_size,
            "iv_file": file.iv_file,
            "encrypted_file": base64.b64encode(file.encrypted_file).decode("utf-8"),
            "assoc_data_file": file.assoc_data_file,
            "created_at": file.created_at.isoformat() if file.created_at else None,
            "dek": {
                "key_id": dek.key_id if is_owner else None,
                "iv_dek": dek.iv_dek if is_owner else None,
                "encrypted_dek": dek.encrypted_dek if is_owner else None,
            },
        },
    }


def upload_file(user_id: str, message: dict[str, Any]) -> dict[str, Any]:
    """Upload a new encrypted file"""
    required_fields = [
        "file_name",
        "encrypted_file",
        "iv_file",
        "iv_dek",
        "encrypted_dek",
        "file_type",
        "file_size",
    ]

    for field in required_fields:
        if field not in message:
            return {"status": "error", "message": f"Missing required field: {field}"}

    try:
        file_id = str(uuid.uuid4())
        key_id = str(uuid.uuid4())
        try:
            encrypted_file_bytes = base64.b64decode(message["encrypted_file"])
        except (binascii.Error, ValueError):
            return {"status": "error", "message": "Invalid base64 encoding for encrypted file"}

        new_file = File(
            File.FileParams(
                file_id=file_id,
                file_name=secure_filename(message["file_name"]),
                iv_file=message["iv_file"],
                encrypted_file=encrypted_file_bytes,
                file_type=message["file_type"],
                file_size=int(message["file_size"]) if message["file_size"] else 0,
            ),
            created_by=user_id,
        )

        new_dek = FileDEK(
            key_id=key_id,
            file_id=file_id,
            iv_dek=message["iv_dek"],
            encrypted_dek=message["encrypted_dek"],
        )

        db.session.add(new_file)
        db.session.add(new_dek)
        db.session.commit()

    except Exception as e:
        db.session.rollback()
        logger.exception("Error uploading file")
        return {"status": "error", "message": f"Error uploading file: {e!s}"}
    else:
        return {
            "status": "success",
            "message": "File uploaded successfully",
            "file_id": file_id,
            "file_name": new_file.file_name,
        }


def validate_share_file_input(message: dict[str, Any]) -> tuple[bool, str]:
    if not message.get("file_id"):
        return False, "Missing file_id"
    if not message.get("shared_with_username"):
        return False, "Missing shared_with_username"
    if not message.get("encrypted_dek") or not message.get("iv_dek"):
        return False, "Missing encryption details"
    return True, ""


def get_share_file_entities(user_id: str, file_id: str, shared_with_username: str) -> tuple[Any, Any, str]:
    file = File.query.filter_by(file_id=file_id, created_by=user_id).first()
    if not file:
        return None, None, "File not found or access denied"
    recipient = UserLogin.query.filter_by(username=shared_with_username).first()
    if not recipient:
        return None, None, "Recipient user not found"
    if recipient.id == user_id:
        return None, None, "Cannot share file with yourself"
    return file, recipient, ""


def check_existing_share(file_id: str, recipient_id: str) -> str:
    existing_share = FileShare.query.filter_by(file_id=file_id, shared_with=recipient_id).first()
    if existing_share:
        return "File already shared with this user"
    return ""


def create_file_share(
    file_id: str,
    recipient: UserLogin,
    encrypted_dek: str,
    iv_dek: str,
    assoc_data_dek: str | None,
) -> tuple[FileShare | None, str]:
    try:
        encrypted_dek_bytes = base64.b64decode(encrypted_dek)
    except (binascii.Error, ValueError):
        return None, "Invalid base64 encoding for encrypted_dek"
    share = FileShare(
        share_id=str(uuid.uuid4()),
        file_id=file_id,
        shared_with=recipient.id,
        encrypted_dek=encrypted_dek_bytes,
        iv_dek=iv_dek,
        assoc_data_dek=assoc_data_dek or f"File of file ID {file_id} shared with {recipient.id}",
    )
    db.session.add(share)
    db.session.commit()
    return share, ""


def validate_share_file_types(
    file_id: str,
    shared_with_username: str,
    encrypted_dek: str,
    iv_dek: str,
) -> tuple[bool, str]:
    if not isinstance(file_id, str) or not file_id:
        return False, "file_id is required and must be a string"
    if not isinstance(shared_with_username, str) or not shared_with_username:
        return False, "shared_with_username is required and must be a string"
    if not isinstance(encrypted_dek, str) or not encrypted_dek:
        return False, "encrypted_dek is required and must be a string"
    if not isinstance(iv_dek, str) or not iv_dek:
        return False, "iv_dek is required and must be a string"
    return True, ""


def process_share_file(
    user_id: str,
    file_id: str,
    shared_with_username: str,
    encrypted_dek: str,
    iv_dek: str,
) -> dict[str, Any]:
    try:
        file, recipient, error = get_share_file_entities(user_id, file_id, shared_with_username)
        if error:
            return {"status": "error", "message": error}
        error = check_existing_share(file_id, recipient.id)
        if error:
            return {"status": "error", "message": error}
        assoc_data_dek = None  # Default value if not provided
        share, error = create_file_share(file_id, recipient, encrypted_dek, iv_dek, assoc_data_dek)
        if error:
            return {"status": "error", "message": error}
        if not share:
            return {"status": "error", "message": "Failed to create file share"}

    except Exception as e:
        db.session.rollback()
        logger.exception("Error sharing file")
        return {"status": "error", "message": f"Error sharing file: {e!s}"}
    else:
        return {
            "status": "success",
            "message": "File shared successfully",
            "share_id": share.share_id,
            "shared_with": recipient.id,
        }


def share_file(user_id: str, message: dict[str, Any]) -> dict[str, Any]:
    """Share a file with another user"""
    file_id = message.get("file_id")
    shared_with_username = message.get("shared_with_username")
    encrypted_dek = message.get("encrypted_dek")
    iv_dek = message.get("iv_dek")
    valid, error = validate_share_file_input(message)
    if not valid:
        return {"status": "error", "message": error}
    valid, error = validate_share_file_types(
        file_id if isinstance(file_id, str) and file_id is not None else "",
        shared_with_username if isinstance(shared_with_username, str) and shared_with_username is not None else "",
        encrypted_dek if isinstance(encrypted_dek, str) and encrypted_dek is not None else "",
        iv_dek if isinstance(iv_dek, str) and iv_dek is not None else "",
    )
    if not valid:
        return {"status": "error", "message": error}
    return process_share_file(
        user_id,
        file_id if isinstance(file_id, str) and file_id is not None else "",
        shared_with_username if isinstance(shared_with_username, str) and shared_with_username is not None else "",
        encrypted_dek if isinstance(encrypted_dek, str) and encrypted_dek is not None else "",
        iv_dek if isinstance(iv_dek, str) and iv_dek is not None else "",
    )


def get_revoke_share_entities(
    user_id: str,
    file_id: str,
    shared_with_username: str,
) -> tuple[Any, Any, Any, str | None]:
    if not file_id:
        return None, None, None, "Missing file_id"
    if not shared_with_username:
        return None, None, None, "Missing shared_with_username"
    file = File.query.filter_by(file_id=file_id, created_by=user_id).first()
    if not file:
        return None, None, None, "File not found or access denied"
    recipient = UserLogin.query.filter_by(username=shared_with_username).first()
    if not recipient:
        return None, None, None, "Recipient user not found"
    share = FileShare.query.filter_by(file_id=file_id, shared_with=recipient.id).first()
    if not share:
        return None, None, None, "Share not found"
    return file, recipient, share, None


def revoke_share(user_id: str, message: dict[str, Any]) -> dict[str, Any]:
    """Revoke a user's access to a shared file"""
    file_id = message.get("file_id")
    shared_with_username = message.get("shared_with_username")

    file_id_str = file_id if isinstance(file_id, str) and file_id is not None else ""
    shared_with_username_str = (
        shared_with_username if isinstance(shared_with_username, str) and shared_with_username is not None else ""
    )

    try:
        file, recipient, share, error_message = get_revoke_share_entities(
            user_id,
            file_id_str,
            shared_with_username_str,
        )
        if error_message:
            return {"status": "error", "message": error_message}
        db.session.delete(share)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.exception("Error revoking share")
        return {"status": "error", "message": f"Error revoking share: {e!s}"}
    else:
        return {
            "status": "success",
            "message": "Access revoked successfully",
        }


def handle_authenticated_command(command: str, message: dict[str, Any], user_id: str) -> dict[str, Any]:
    command_map = {
        "list_files": lambda: list_files(user_id),
        "list_shared_files": lambda: list_shared_files(user_id),
        "upload_file": lambda: upload_file(user_id, message),
        "share_file": lambda: share_file(user_id, message),
        "revoke_share": lambda: revoke_share(user_id, message),
    }

    if command in command_map:
        return command_map[command]()

    if command == "list_file_shares":
        file_id = message.get("file_id")
        if not isinstance(file_id, str) or not file_id:
            return {"status": "error", "message": "file_id is required for list_file_shares"}
        return list_file_shares(user_id, file_id)

    if command == "download_file":
        file_id = message.get("file_id")
        if not isinstance(file_id, str) or not file_id:
            return {"status": "error", "message": "file_id is required for download_file"}
        return download_file(user_id, file_id)

    return {"status": "error", "message": f"Unknown command: {command}"}


def handle_message(message: dict[str, Any]) -> dict[str, Any]:
    """Handle a message based on its command"""
    try:
        command = message.get("command")
        if not command:
            return {"status": "error", "message": "No command specified"}
        if command == "login":
            return authenticate_user(message)
        token = message.get("token")
        if not token:
            return {"status": "error", "message": "Authentication token required"}
        try:
            user_id = validate_token(token)
            return handle_authenticated_command(command, message, user_id)
        except ValueError as e:
            return {"status": "error", "message": str(e)}
    except Exception as e:
        logger.exception("Error handling message")
        return {"status": "error", "message": f"Internal error: {e!s}"}
