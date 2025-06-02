from __future__ import annotations  # noqa: INP001

import base64
import binascii
import datetime
import re
import uuid

import jwt
from argon2 import PasswordHasher
from argon2 import Type as Argon2Type
from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Blueprint, current_app, request
from flask_restx import Namespace, Resource
from sqlalchemy.exc import SQLAlchemyError

from app import db
from app.docs.auth_docs import register_auth_models
from app.models.file import File, FileDEK
from app.models.user import UserKEK, UserLogin
from app.utils.tofu import calculate_key_fingerprint, verify_tofu_key
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
    except (binascii.Error, ValueError):
        return False, f"Invalid base64 encoding for {name}"
    else:
        return True, ""


def validate_iv(iv: str) -> tuple[bool, str]:
    """Validate that IV is correct size (96 bits / 12 bytes)"""
    try:
        decoded = base64.b64decode(iv)
        if len(decoded) != IV_BYTE_LENGTH:
            return False, f"IV must be 96 bits ({IV_BYTE_LENGTH} bytes)"
    except (binascii.Error, ValueError):
        return False, "Invalid IV format"
    else:
        return True, ""


def handle_error(error: Exception | str, code: int = 500) -> tuple:
    """Handle errors and return a JSON response"""
    return {"message": str(error) if not isinstance(error, str) else error}, code


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
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})*$"
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
        required=["username", "auth_password", "email", "iv_KEK", "encrypted_KEK", "public_key", "p", "salt", "m", "t"],
        base64_fields=["iv_KEK", "encrypted_KEK", "public_key"],
        iv_fields=["iv_KEK"],
    )
    if error:
        return error
    current_app.logger.info("Checking email & username")
    error = check_email_and_username(data["email"], data["username"])
    if error:
        return error
    current_app.logger.info("Validating KEK")
    try:
        if not base64.b64decode(data["encrypted_KEK"]):
            return "Invalid encrypted_KEK format"
    except (binascii.Error, ValueError):
        return "Invalid encrypted_KEK format"
    current_app.logger.info("Validating public key")
    error = validate_public_key(data["public_key"])
    if error:
        return error
    return None


def validate_public_key(public_key: str) -> str | None:
    try:
        public_key_bytes = base64.b64decode(public_key)

        try:
            decoded_str = public_key_bytes.decode("utf-8", errors="replace")
            if decoded_str.startswith("ssh-ed25519"):
                return (
                    "SSH format keys are not supported. Please provide an Ed25519 key in PEM format "
                    "(Encoded in Base64)."
                )
        except UnicodeDecodeError:
            pass

        try:
            loaded_public_key = serialization.load_pem_public_key(public_key_bytes)
            if not isinstance(loaded_public_key, Ed25519PublicKey):
                return "Public key must be an Ed25519 public key in PEM format"
        except (ValueError, TypeError) as e:
            current_app.logger.exception("Public key validation error", exc_info=e)
            return f"Invalid public key format: {e!s}"
        else:
            return None
    except (binascii.Error, ValueError) as e:
        current_app.logger.exception("Base64 decoding error for public key", exc_info=e)
        return f"Invalid base64 encoding for public_key: {e!s}"


@auth_ns.route("/register")
class Register(Resource):
    @auth_ns.expect(models["register_model"])
    @auth_ns.response(201, "User created successfully!")
    @auth_ns.response(400, "Validation error")
    @auth_ns.response(409, "Username already exists!")
    def post(self) -> object:
        """Register a new user with TOFU key verification"""
        try:
            data = request.get_json()
            current_app.logger.info("Received registration request for username: %s", data.get("username"))

            error = validate_register_data(data)
            if error:
                current_app.logger.warning("Registration validation error: %s", error)
                return handle_error(error, 400 if error != "Username already exists!" else 409)

            user_id = str(uuid.uuid4())

            argon2_p = int(current_app.config.get("ARGON2_PARALLELISM", 2))
            argon2_m = int(current_app.config.get("ARGON2_MEMORY_COST", 65536))
            argon2_t = int(current_app.config.get("ARGON2_TIME_COST", 3))

            ph = PasswordHasher(
                time_cost=argon2_t,
                memory_cost=argon2_m,
                parallelism=argon2_p,
                hash_len=32,
                salt_len=16,
                type=Argon2Type.ID,
            )
            hashed_password = ph.hash(data["auth_password"])

            new_user = UserLogin(user_id, data["username"], hashed_password, data["email"], data["public_key"])

            new_kek = UserKEK(
                key_id=str(uuid.uuid4()),
                user_id=user_id,
                kek_params=UserKEK.KEKParams(
                    iv_kek=data["iv_KEK"],
                    encrypted_kek=data["encrypted_KEK"],
                    assoc_data_kek=f"User Key Encryption Key for {user_id}",
                    salt=data.get("salt", ""),
                    p=int(data.get("p", 0)),
                    m=int(data.get("m", 0)),
                    t=int(data.get("t", 0)),
                ),
            )

            try:
                db.session.add(new_user)
                db.session.add(new_kek)
                db.session.commit()

                is_trusted, tofu_message, _ = verify_tofu_key(user_id, data["public_key"])
                if not is_trusted:
                    db.session.delete(new_user)
                    db.session.delete(new_kek)
                    db.session.commit()
                    return handle_error(f"Key verification failed: {tofu_message}", 400)

                key_fingerprint = calculate_key_fingerprint(data["public_key"])
                current_app.logger.info(
                    "User created successfully: %s with key fingerprint: %s",
                    user_id,
                    key_fingerprint,
                )

            except SQLAlchemyError as e:
                db.session.rollback()
                current_app.logger.exception("Database error during registration", exc_info=e)
                return {"message": f"Error creating user: {e!s}"}, 500

        except Exception:
            current_app.logger.exception("Unexpected error in registration")
            return {"message": "Server error processing registration"}, 500
        else:
            return {
                "message": "User created successfully!",
                "user_id": user_id,
                "key_fingerprint": key_fingerprint,
                "tofu_message": tofu_message,
            }, 201


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
        dek = AESGCM(kek).decrypt(iv_dek, encrypted_dek, None)

        iv_file = base64.b64decode(file.iv_file)
        try:
            decrypted_content = AESGCM(dek).decrypt(iv_file, file.encrypted_file, None)
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

    @auth_ns.response(200, "User information returned")
    @auth_ns.response(404, "User not found")
    @auth_ns.marshal_with(models["get_user_info_response_model"])
    def get(self, user_id: str) -> object:
        """Get all information for a user, their KEK, and their files"""
        user = UserLogin.query.filter_by(id=user_id).first()
        if not user:
            return handle_error(Exception("User not found!"), 404)

        kek = UserKEK.query.filter_by(user_id=user_id).first()

        files = File.query.filter_by(created_by=user_id).all()
        files_info = []
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
            files_info.append(file_info)

        user_info = {
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "public_key": user.public_key,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "modified_at": user.modified_at.isoformat() if user.modified_at else None,
        }

        if kek and kek.kek_params:
            user_info.update(
                {
                    "key_id": kek.key_id,
                    "iv_KEK": kek.kek_params.iv_kek,
                    "encrypted_KEK": kek.kek_params.encrypted_kek,
                    "assoc_data_KEK": kek.kek_params.assoc_data_kek,
                    "salt": kek.kek_params.salt,
                    "p": kek.kek_params.p,
                    "m": kek.kek_params.m,
                    "t": kek.kek_params.t,
                    "kek_created_at": kek.created_at.isoformat() if kek.created_at else None,
                },
            )

        user_info["files"] = files_info

        return user_info, 200


@auth_ns.route("/users")
class GetAllUsers(Resource):
    @auth_ns.marshal_with(models["get_all_users_response_model"])
    @auth_ns.response(200, "All users retrieved successfully")
    @auth_ns.response(500, "Server error")
    def get(self) -> object:
        """Get all usernames and emails"""
        try:
            users = UserLogin.query.order_by(UserLogin.username).all()

            users_list = [
                {
                    "username": user.username,
                    "email": user.email,
                }
                for user in users
            ]
        except SQLAlchemyError as e:
            current_app.logger.exception("Database error retrieving users", exc_info=e)
            return handle_error(f"Error retrieving users: {e!s}", 500)
        except Exception as e:
            current_app.logger.exception("Unexpected error retrieving users", exc_info=e)
            return handle_error("Server error retrieving users", 500)
        else:
            return {"users": users_list}, 200
