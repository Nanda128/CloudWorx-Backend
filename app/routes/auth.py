from __future__ import annotations

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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Blueprint, current_app, request
from flask_restx import Namespace, Resource
from sqlalchemy.exc import SQLAlchemyError

from app import db
from app.docs.auth_docs import register_auth_models
from app.models.user import UserKEK, UserLogin
from app.utils.tofu import calculate_key_fingerprint, verify_tofu_key
from app.utils.token import token_required

auth_bp = Blueprint("auth", __name__)
auth_ns = Namespace("auth", description="Authentication and user management")

MIN_PASSWORD_LENGTH = 12
IV_BYTE_LENGTH = 12
ARGON2_HASH_PARTS_MIN_LENGTH = 5

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


def is_base64_and_pem_encoded_public_key(public_key: str) -> bool:
    """Check if the public_key is base64 encoded and then PEM encoded.

    Decodes base64, then checks for PEM header/footer.
    """
    try:
        decoded = base64.b64decode(public_key)
        pem_str = decoded.decode("utf-8")
        return pem_str.startswith("-----BEGIN PUBLIC KEY-----") and pem_str.strip().endswith("-----END PUBLIC KEY-----")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False


def validate_register_data(data: dict) -> str | None:
    error = check_fields(
        data,
        required=["username", "auth_password", "email", "iv_KEK", "encrypted_KEK", "public_key", "p", "salt", "m", "t"],
        base64_fields=["iv_KEK", "encrypted_KEK", "public_key"],
        iv_fields=["iv_KEK"],
    )
    if not error:
        current_app.logger.info("Checking email & username")
        error = check_email_and_username(data["email"], data["username"])
    if not error:
        current_app.logger.info("Validating KEK")
        try:
            if not base64.b64decode(data["encrypted_KEK"]):
                error = "Invalid encrypted_KEK format"
        except (binascii.Error, ValueError):
            error = "Invalid encrypted_KEK format"
    if not error and not is_base64_and_pem_encoded_public_key(data["public_key"]):
        error = "public_key must be base64 encoded and PEM encoded"
    if not error:
        try:
            base64.b64decode(data["public_key"]).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            error = "Invalid public key encoding"
    return error


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
                return {"message": error}, 400

            user_id = str(uuid.uuid4())

            argon2_p = int(current_app.config.get("ARGON2_PARALLELISM", 1))
            argon2_m = int(current_app.config.get("ARGON2_MEMORY_COST", 12288))
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

            decoded_public_key = base64.b64decode(data["public_key"]).decode("utf-8")

            new_user = UserLogin(user_id, data["username"], hashed_password, data["email"], decoded_public_key)

            new_kek = UserKEK(
                key_id=str(uuid.uuid4()),
                user_id=user_id,
                kek_params=UserKEK.KEKParams(
                    iv_kek=data["iv_KEK"],
                    encrypted_kek=data["encrypted_KEK"],
                    assoc_data_kek=f"User Key Encryption Key for {user_id}",
                    salt=data.get("salt", ""),
                    p=int(data.get("p", argon2_p)),
                    m=int(data.get("m", argon2_m)),
                    t=int(data.get("t", argon2_t)),
                ),
            )

            try:
                db.session.add(new_user)
                db.session.add(new_kek)
                db.session.commit()

                is_trusted, tofu_message, _ = verify_tofu_key(user_id, decoded_public_key)
                if not is_trusted:
                    db.session.delete(new_kek)
                    db.session.delete(new_user)
                    db.session.commit()
                    return {"message": tofu_message}, 400

                key_fingerprint = calculate_key_fingerprint(decoded_public_key)
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


@auth_ns.route("/login")
class Login(Resource):
    @auth_ns.expect(models["login_model"])
    @auth_ns.response(200, "Login successful", models["login_info_model"])
    @auth_ns.response(400, "Missing required field")
    @auth_ns.response(404, "Invalid username")
    @auth_ns.response(401, "Invalid authentication password")
    def post(self) -> object:
        """Login a user and return a JWT token"""
        data = request.get_json()

        for field in ["username", "entered_auth_password"]:
            if field not in data:
                return {"message": f"Missing required field: {field}"}, 400

        user = UserLogin.query.filter_by(username=data["username"]).first()
        if not user:
            return {"message": "Invalid username!"}, 404

        try:
            PasswordHasher().verify(user.auth_password, data["entered_auth_password"])
        except VerifyMismatchError:
            return {"message": "Invalid authentication password!"}, 401

        jwt_secret = current_app.config["JWT_SECRET_KEY"]
        if not jwt_secret:
            return {"message": "JWT secret key is not set in environment variables!"}, 500

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
    @auth_ns.doc(security="apikey")
    @auth_ns.expect(models["change_auth_password_model"])
    @auth_ns.response(200, "Authentication password changed successfully!")
    @auth_ns.response(400, "Validation error")
    @auth_ns.response(401, "Invalid old authentication password")
    @auth_ns.response(404, "Invalid username or user not found")
    @token_required
    def put(self, current_user: UserLogin) -> object:
        """Change the authentication password for a user"""
        data = request.get_json()

        for field in ["old_auth_password", "new_auth_password"]:
            if field not in data:
                return {"message": f"Missing required field: {field}"}, 400

        user = UserLogin.query.filter_by(username=current_user.id).first()
        if not user:
            return {"message": "Invalid username or user not found!"}, 404

        try:
            PasswordHasher().verify(user.auth_password, data["old_auth_password"])
        except VerifyMismatchError:
            return {"message": "Invalid old authentication password!"}, 401

        if data["old_auth_password"] == data["new_auth_password"]:
            return {"message": "New authentication password cannot be the same as the old one!"}, 400

        user.auth_password = data["new_auth_password"]

        db.session.commit()

        return {"message": "Authentication password changed successfully!"}, 200


@auth_ns.route("/encryption-password")
class ChangeEncryptionPassword(Resource):
    @auth_ns.doc(security="apikey")
    @auth_ns.expect(models["change_encryption_password_model"])
    @auth_ns.response(200, "Encryption password changed successfully!")
    @auth_ns.response(400, "Validation error")
    @auth_ns.response(401, "Invalid password")
    @auth_ns.response(404, "User not found")
    @token_required
    def put(self, current_user: UserLogin) -> object:
        """Change the encryption password for a user"""
        data = request.get_json()

        error = check_fields(
            data,
            required=[
                "old_password_derived_key",
                "new_password_derived_key",
                "new_iv_KEK",
                "new_encrypted_KEK",
            ],
            base64_fields=["new_iv_KEK", "new_encrypted_KEK"],
            iv_fields=["new_iv_KEK"],
        )
        if error:
            return {"message": error}, 400

        user = UserLogin.query.filter_by(username=current_user.id).first()
        if not user:
            return {"message": "User not found!"}, 404
        kek_data = UserKEK.query.filter_by(user_id=user.id).first()
        if not kek_data:
            return {"message": "User KEK not found!"}, 404

        error = verify_password_and_kek(data["old_password_derived_key"], kek_data)
        if error:
            code = 401 if "password" in error or "Authentication failed" in error else 400
            return {"message": error}, code

        kek_data.iv_KEK = data["new_iv_KEK"]
        kek_data.encrypted_KEK = data["new_encrypted_KEK"]

        db.session.commit()
        return {"message": "Encryption password changed successfully!"}, 200


@auth_ns.route("/<user_id>")
class DeleteUser(Resource):
    @auth_ns.doc(security="apikey")
    @auth_ns.expect(models["delete_user_model"])
    @auth_ns.response(200, "User deleted successfully!")
    @auth_ns.response(400, "Missing required field")
    @auth_ns.response(401, "Invalid password")
    @auth_ns.response(404, "User not found")
    @token_required
    def delete(self, user_id: str) -> object:
        """Delete a user and their KEK after verifying password"""
        data = request.get_json()
        if not data or "password" not in data:
            return {"message": "Missing required field: password"}, 400

        user = UserLogin.query.filter_by(id=user_id).first()
        if not user:
            return {"message": "User not found!"}, 404

        try:
            PasswordHasher().verify(user.auth_password, data["password"])
        except VerifyMismatchError:
            return {"message": "Invalid password!"}, 401

        kek = UserKEK.query.filter_by(user_id=user_id).first()
        if kek:
            db.session.delete(kek)
        db.session.delete(user)
        db.session.commit()

        return {"message": "User deleted successfully!"}, 200

    @auth_ns.response(200, "User information returned", models["get_user_info_response_model"])
    @auth_ns.response(404, "User not found")
    @token_required
    @auth_ns.doc(security="apikey")
    def get(self, user_id: str) -> object:
        """Get all information for a user, their KEK, and their files"""
        user = UserLogin.query.filter_by(id=user_id).first()
        if not user:
            return {"message": "User not found!"}, 404

        kek = UserKEK.query.filter_by(user_id=user_id).first()

        user_info = {
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "public_key": user.public_key,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "modified_at": user.modified_at.isoformat() if user.modified_at else None,
        }

        if kek:
            user_info.update(
                {
                    "key_id": kek.key_id,
                    "iv_KEK": kek.iv_kek,
                    "encrypted_KEK": kek.encrypted_kek,
                    "assoc_data_KEK": kek.assoc_data_kek,
                    "salt": kek.salt,
                    "p": kek.p,
                    "m": kek.m,
                    "t": kek.t,
                    "kek_created_at": kek.created_at.isoformat() if kek.created_at else None,
                },
            )

        return user_info, 200


@auth_ns.route("/users")
class GetAllUsers(Resource):
    @auth_ns.response(200, "All users retrieved successfully", models["get_all_users_response_model"])
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
            return {"message": "Database error retrieving users"}, 500
        except Exception as e:
            current_app.logger.exception("Unexpected error retrieving users", exc_info=e)
            return {"message": "Server error retrieving users"}, 500
        else:
            return {"users": users_list}, 200
