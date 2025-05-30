from __future__ import annotations  # noqa: INP001

import base64
import binascii
import datetime
import re
import uuid

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Blueprint, current_app, request
from flask_restx import Namespace, Resource

from app import db
from app.docs.auth_docs import register_auth_models
from app.models.file import File, FileDEK
from app.models.user import UserKEK, UserLogin
from app.utils.token import token_required

auth_bp = Blueprint("auth", __name__)
auth_ns = Namespace("auth", description="Authentication and user management")

MIN_PASSWORD_LENGTH = 12
IV_BYTE_LENGTH = 12

models = register_auth_models(auth_ns)


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate that password meets complexity requirements"""
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"

    return True, ""


def validate_base64(value: str, name: str) -> tuple[bool, str]:
    """Validate that a value is a valid base64 string"""
    try:
        base64.b64decode(value)
        return True, ""  # noqa: TRY300
    except (binascii.Error, ValueError):
        return False, f"Invalid base64 encoding for {name}"


def validate_iv(iv: str) -> tuple[bool, str]:
    """Validate that IV is correct size (96 bits / 12 bytes)"""
    try:
        decoded = base64.b64decode(iv)
        if len(decoded) != IV_BYTE_LENGTH:
            return False, f"IV must be 96 bits ({IV_BYTE_LENGTH} bytes)"
        return True, ""  # noqa: TRY300
    except (binascii.Error, ValueError):
        return False, "Invalid IV format"


def handle_error(error: Exception, code: int = 500) -> tuple:
    """Handle errors and return a JSON response"""
    return {"message": str(error)}, code


def check_fields(
    data: dict,
    required: list[str] | None = None,
    base64_fields: list[str] | None = None,
    iv_fields: list[str] | None = None,
) -> str | None:
    required = required or []
    base64_fields = base64_fields or []
    iv_fields = iv_fields or []
    for field in required:
        if not data.get(field):
            return f"Missing required field: {field}"
    for field in base64_fields:
        is_valid, error = validate_base64(data[field], field)
        if not is_valid:
            return error
    for field in iv_fields:
        is_valid, error = validate_iv(data[field])
        if not is_valid:
            return error
    return None


def check_email_and_username(email: str, username: str) -> str | None:
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(email_pattern, email):
        return "Invalid email format"
    if not re.match(r"^[A-Za-z0-9_-]+$", username):
        return "Username can only contain letters, numbers, hyphens, and underscores"
    if UserLogin.query.filter_by(username=username).first():
        return "Username already exists!"
    return None


def validate_register_data(data: dict) -> str | None:
    error = check_fields(
        data,
        required=["username", "auth_password", "email", "iv_KEK", "encrypted_KEK", "public_key"],
        base64_fields=["iv_KEK", "encrypted_KEK", "public_key"],
        iv_fields=["iv_KEK"],
    )
    if error:
        return error
    error = check_email_and_username(data["email"], data["username"])
    if error:
        return error
    try:
        if not base64.b64decode(data["encrypted_KEK"]):
            return "Invalid encrypted_KEK format"
    except (binascii.Error, ValueError):
        return "Invalid encrypted_KEK format"
    error = validate_public_key(data["public_key"])
    if error:
        return error
    return None


def validate_public_key(public_key: str) -> str | None:
    try:
        public_key_bytes = base64.b64decode(public_key)
    except (binascii.Error, ValueError):
        return "Invalid base64 encoding for public_key"
    try:
        loaded_public_key = serialization.load_pem_public_key(public_key_bytes)
    except (ValueError, TypeError):
        return "Invalid public_key format or not a valid PEM-encoded Ed25519 public key"
    if not isinstance(loaded_public_key, Ed25519PublicKey):
        return "Public key must be an Ed25519 public key in PEM format"
    return None


@auth_ns.route("/register")
class Register(Resource):
    @auth_ns.expect(models["register_model"])
    @auth_ns.response(201, "User created successfully!")
    @auth_ns.response(400, "Validation error")
    @auth_ns.response(409, "Username already exists!")
    def post(self) -> object:
        """Register a new user"""
        data = request.get_json()

        error = validate_register_data(data)
        if error:
            return handle_error(Exception(error), 400 if error != "Username already exists!" else 409)

        user_id = str(uuid.uuid4())

        new_user = UserLogin(user_id, data["username"], data["auth_password"], data["email"], data["public_key"])

        new_kek = UserKEK(
            key_id=str(uuid.uuid4()),
            user_id=user_id,
            kek_params=UserKEK.KEKParams(
                iv_kek=data["iv_KEK"],
                encrypted_kek=data["encrypted_KEK"],
                assoc_data_kek=f"User Key Encryption Key for {user_id}",
            ),
        )

        db.session.add(new_user)
        db.session.add(new_kek)
        db.session.commit()

        return {"message": "User created successfully!", "user_id": user_id}, 201


def validate_retrieve_files_data(data: dict) -> str | None:
    error = check_fields(data, required=["username", "password_derived_key"])
    if error:
        return error
    if not isinstance(data["username"], str) or not isinstance(data["password_derived_key"], str):
        return "Username and password derived key must be strings"
    return None


def get_user_and_kek(username: str) -> tuple:
    user = UserLogin.query.filter_by(username=username).first()
    if not user:
        return None, None, "User not found!"
    kek_data = UserKEK.query.filter_by(user_id=user.id).first()
    if not kek_data:
        return user, None, "User KEK not found!"
    return user, kek_data, None


def verify_password_and_kek(password_derived_key: str, kek_data: UserKEK) -> str | None:
    try:
        password_key = base64.b64decode(password_derived_key)
    except (binascii.Error, ValueError) as e:
        return "Authentication failed: " + str(e)
    if not kek_data.encrypted_kek or not kek_data.iv_kek:
        return "Missing KEK or IV for user!"
    try:
        encrypted_kek = base64.b64decode(kek_data.encrypted_kek)
        iv_kek = base64.b64decode(kek_data.iv_kek)
        AESGCM(password_key).decrypt(iv_kek, encrypted_kek, None)
    except InvalidTag:
        return "Invalid password!"
    return None


def decrypt_user_files(user: UserLogin, kek_data: UserKEK, password_derived_key: str) -> list[dict]:
    """Decrypt all files for a user using their password-derived-key and KEK"""
    password_key = base64.b64decode(password_derived_key)
    encrypted_kek = base64.b64decode(kek_data.encrypted_kek)
    iv_kek = base64.b64decode(kek_data.iv_kek)
    kek = AESGCM(password_key).decrypt(iv_kek, encrypted_kek, None)

    files = File.query.filter_by(created_by=user.id).all()
    file_ids = [f.file_id for f in files]
    if not file_ids:
        return []

    deks = FileDEK.query.filter(
        db.or_(*[FileDEK.file_id == file_id for file_id in file_ids]),
    ).all()
    dek_map = {dek.file_id: dek for dek in deks}

    decrypted_files = []
    for file in files:
        dek = dek_map.get(file.file_id)
        if not dek:
            continue

        encrypted_dek = base64.b64decode(dek.encrypted_dek)
        iv_dek = base64.b64decode(dek.iv_dek)
        dek_bytes = AESGCM(kek).decrypt(iv_dek, encrypted_dek, None)

        iv_file = base64.b64decode(file.iv_file)
        try:
            decrypted_content = AESGCM(dek_bytes).decrypt(iv_file, file.encrypted_file, None)
        except InvalidTag:
            decrypted_content = None

        decrypted_files.append(
            {
                "file_id": file.file_id,
                "file_name": file.file_name,
                "decrypted_content": base64.b64encode(decrypted_content).decode("utf-8") if decrypted_content else None,
                "created_at": (
                    file.created_at.isoformat() if hasattr(file, "created_at") and file.created_at is not None else None
                ),
            },
        )
    return decrypted_files


@auth_ns.route("/retrieve-files")
class RetrieveFiles(Resource):
    @auth_ns.expect(models["retrieve_files_model"])
    @auth_ns.marshal_with(models["retrieve_files_response_model"])
    @auth_ns.response(200, "Files retrieved")
    @auth_ns.response(400, "Validation error")
    @auth_ns.response(404, "User not found")
    def post(self) -> object:
        """Retrieve files for a user"""
        data = request.get_json()

        error = validate_retrieve_files_data(data)
        if error:
            return handle_error(Exception(error), 400)

        user, kek_data, error = get_user_and_kek(data["username"])
        if error:
            return handle_error(Exception(error), 404)

        if not user or not kek_data:
            return handle_error(Exception("User not found!" if not user else "User KEK not found!"), 404)

        error = verify_password_and_kek(data["password_derived_key"], kek_data)
        if error:
            return handle_error(Exception(error), 401 if "password" in error else 500)

        jwt_secret = current_app.config["JWT_SECRET_KEY"]
        if not jwt_secret:
            return handle_error(Exception("JWT secret key is not set in environment variables!"), 500)

        token = jwt.encode(
            {"user_id": user.id, "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)},
            jwt_secret,
        )

        decrypted_files = decrypt_user_files(user, kek_data, data["password_derived_key"])

        return {"token": token, "user_id": user.id, "username": user.username, "files": decrypted_files}, 200


@auth_ns.route("/login")
class Login(Resource):
    @auth_ns.expect(models["login_model"])
    @auth_ns.marshal_with(models["login_info_model"])
    @auth_ns.response(200, "Login successful")
    @auth_ns.response(400, "Missing required field")
    @auth_ns.response(404, "Invalid username")
    @auth_ns.response(401, "Invalid authentication password")
    def post(self) -> object:
        """Login a user and return a JWT token"""
        data = request.get_json()

        for field in ["username", "entered_auth_password"]:
            if field not in data:
                return handle_error(Exception(f"Missing required field: {field}"), 400)

        user = UserLogin.query.filter_by(username=data["username"]).first()
        if not user:
            return handle_error(Exception("Invalid username!"), 404)

        try:
            PasswordHasher().verify(user.auth_password, data["entered_auth_password"])
        except VerifyMismatchError:
            return handle_error(Exception("Invalid authentication password!"), 401)

        files = File.query.filter_by(created_by=user.id).all()
        user_files_info = []
        for file in files:
            file_info = {
                "file_id": file.file_id,
                "file_name": file.file_name,
                "file_type": None,
                "file_size": None,
            }
            if file.file_name and "." in file.file_name:
                file_info["file_type"] = file.file_name.rsplit(".", 1)[-1].lower()
            if file.encrypted_file is not None:
                file_info["file_size"] = len(file.encrypted_file)
            user_files_info.append(file_info)

        jwt_secret = current_app.config["JWT_SECRET_KEY"]
        if not jwt_secret:
            return handle_error(Exception("JWT secret key is not set in environment variables!"), 500)

        token = jwt.encode(
            {"user_id": user.id, "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)},
            jwt_secret,
        )

        return {
            "token": token,
            "user_id": user.id,
            "files": user_files_info,
        }, 200


@auth_ns.route("/auth-password")
class ChangeAuthPassword(Resource):
    @auth_ns.expect(models["change_auth_password_model"])
    @auth_ns.response(200, "Authentication password changed successfully!")
    @auth_ns.response(400, "Validation error")
    @auth_ns.response(401, "Invalid old authentication password")
    @auth_ns.response(404, "Invalid username or user not found")
    @token_required
    def put(self) -> object:
        """Change the authentication password for a user"""
        data = request.get_json()

        for field in ["username", "old_auth_password", "new_auth_password"]:
            if field not in data:
                return handle_error(Exception(f"Missing required field: {field}"), 400)

        user = UserLogin.query.filter_by(username=data["username"]).first()
        if not user:
            return handle_error(Exception("Invalid username or user not found!"), 404)

        try:
            PasswordHasher().verify(user.auth_password, data["old_auth_password"])
        except VerifyMismatchError:
            return handle_error(Exception("Invalid old authentication password!"), 401)

        if data["old_auth_password"] == data["new_auth_password"]:
            return handle_error(Exception("New authentication password must be different from the old one"), 400)

        user.auth_password = data["new_auth_password"]

        db.session.commit()

        return {"message": "Authentication password changed successfully!"}, 200


@auth_ns.route("/encryption-password")
class ChangeEncryptionPassword(Resource):
    @auth_ns.expect(models["change_encryption_password_model"])
    @auth_ns.response(200, "Encryption password changed successfully!")
    @auth_ns.response(400, "Validation error")
    @auth_ns.response(401, "Invalid password")
    @auth_ns.response(404, "User not found")
    @token_required
    def put(self) -> object:
        """Change the encryption password for a user"""
        data = request.get_json()

        error = check_fields(
            data,
            required=[
                "username",
                "old_password_derived_key",
                "new_password_derived_key",
                "new_iv_KEK",
                "new_encrypted_KEK",
            ],
            base64_fields=["old_password_derived_key", "new_iv_KEK", "new_encrypted_KEK"],
            iv_fields=["new_iv_KEK"],
        )
        if error:
            return handle_error(Exception(error), 400)

        user = UserLogin.query.filter_by(username=data["username"]).first()
        if not user:
            return handle_error(Exception("User not found!"), 404)
        kek_data = UserKEK.query.filter_by(user_id=user.id).first()
        if not kek_data:
            return handle_error(Exception("User KEK not found!"), 404)

        error = verify_password_and_kek(data["old_password_derived_key"], kek_data)
        if error:
            code = 401 if "password" in error or "Authentication failed" in error else 400
            return handle_error(Exception(error), code)

        kek_data.iv_KEK = data["new_iv_KEK"]
        kek_data.encrypted_KEK = data["new_encrypted_KEK"]

        db.session.commit()
        return {"message": "Encryption password changed successfully!"}, 200


@auth_ns.route("/<user_id>")
class DeleteUser(Resource):
    @auth_ns.expect(models["delete_user_model"])
    @auth_ns.response(200, "User deleted successfully!")
    @auth_ns.response(400, "Missing required field")
    @auth_ns.response(401, "Invalid password")
    @auth_ns.response(404, "User not found")
    def delete(self, user_id: str) -> object:
        """Delete a user and their KEK after verifying password"""
        data = request.get_json()
        if not data or "password" not in data:
            return handle_error(Exception("Missing required field: password"), 400)

        user = UserLogin.query.filter_by(id=user_id).first()
        if not user:
            return handle_error(Exception("User not found!"), 404)

        try:
            PasswordHasher().verify(user.auth_password, data["password"])
        except VerifyMismatchError:
            return handle_error(Exception("Invalid password!"), 401)

        kek = UserKEK.query.filter_by(user_id=user_id).first()
        if kek:
            db.session.delete(kek)
        db.session.delete(user)
        db.session.commit()

        return {"message": "User deleted successfully!"}, 200


@auth_ns.route("/user-id")
class GetUserId(Resource):
    @auth_ns.expect(models["user_id_model"])
    @auth_ns.marshal_with(models["get_user_id_response_model"])
    @auth_ns.response(200, "User ID returned")
    @auth_ns.response(400, "Missing required field")
    @auth_ns.response(404, "User not found")
    def post(self) -> object:
        """Return the user_id for a given username"""
        data = request.get_json()
        if not data or "username" not in data:
            return handle_error(Exception("Missing required field: username"), 400)

        user = UserLogin.query.filter_by(username=data["username"]).first()
        if not user:
            return handle_error(Exception("User not found!"), 404)

        return {"user_id": user.id}, 200
