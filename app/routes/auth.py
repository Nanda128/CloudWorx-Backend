from __future__ import annotations  # noqa: INP001

import base64
import binascii
import datetime
import re
import uuid
from functools import wraps
from typing import Callable

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Blueprint, current_app, jsonify, request

from app import db
from app.models.file import File, FileDEK
from app.models.user import UserKEK, UserLogin

auth_bp = Blueprint("auth", __name__)

ARGON2ID_PARAM_COUNT = 3
MIN_PASSWORD_LENGTH = 12
IV_BYTE_LENGTH = 12


def token_required(f: Callable) -> Callable:
    """Check if the request has a valid JWT token"""

    @wraps(f)
    def decorated(*args: object, **kwargs: object) -> object:
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]

        if not token:
            return jsonify({"message": "Token is missing!"}), 401

        try:
            jwt_secret = current_app.config["JWT_SECRET_KEY"]
            if jwt_secret is None:
                return jsonify(
                    {"message": "JWT secret key is not set in environment variables!"},
                ), 500
            data = jwt.decode(token, jwt_secret, algorithms=["HS256"])
            current_user = UserLogin.query.filter_by(id=data["user_id"]).first()
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token is invalid!"}), 401

        return f(current_user, *args, **kwargs)

    return decorated


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


def validate_argon2id_params(params: list) -> tuple[bool, str]:
    """Validate Argon2id parameters"""
    if not isinstance(params, list) or len(params) != ARGON2ID_PARAM_COUNT:
        return False, f"Argon2id parameters must be an array with {ARGON2ID_PARAM_COUNT} elements"

    if not all(isinstance(p, int) for p in params):
        return False, "All Argon2id parameters must be integers"

    p, m, t = params

    if p <= 0 or m <= 0 or t <= 0:
        return False, "Argon2id parameters must be positive"

    return True, ""


def handle_error(error: Exception, code: int = 500) -> tuple:
    """Handle errors and return a JSON response"""
    return jsonify({"message": str(error)}), code


def check_fields(
    data: dict,
    required: list[str] | None = None,
    base64_fields: list[str] | None = None,
    iv_fields: list[str] | None = None,
    argon2id_fields: list[str] | None = None,
) -> str | None:
    """Return a generic field checker for required, base64, iv, and argon2id fields."""
    required = required or []
    base64_fields = base64_fields or []
    iv_fields = iv_fields or []
    argon2id_fields = argon2id_fields or []

    for field in required:
        if field not in data or not data[field]:
            return f"Missing required field: {field}"
    for field in base64_fields:
        is_valid, error = validate_base64(data[field], field)
        if not is_valid:
            return error
    for field in iv_fields:
        is_valid, error = validate_iv(data[field])
        if not is_valid:
            return error
    for field in argon2id_fields:
        is_valid, error = validate_argon2id_params(data[field])
        if not is_valid:
            return error
    return None


def check_email_and_username(email: str, username: str) -> str | None:
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(email_pattern, email):
        return "Invalid email format"
    if not re.match(r"^[A-Za-z0-9_-]+$", username):
        return "Username can only contain letters, numbers, hyphens, and underscores"
    return None


def check_user_exists(username: str) -> str | None:
    existing_user = UserLogin.query.filter_by(username=username).first()
    if existing_user and existing_user.username == username:
        return "Username already exists!"
    return None


def validate_register_data(data: dict) -> str | None:
    error = check_fields(
        data,
        required=[
            "username",
            "auth_password",
            "email",
            "salt",
            "iv_KEK",
            "encrypted_KEK",
            "verification_code",
            "verification_iv",
            "argon2id_params",
            "auth_argon2id_params",
            "auth_salt",
        ],
        base64_fields=[
            "salt",
            "iv_KEK",
            "encrypted_KEK",
            "verification_code",
            "verification_iv",
            "auth_salt",
        ],
        iv_fields=["iv_KEK", "verification_iv"],
        argon2id_fields=["auth_argon2id_params", "argon2id_params"],
    )
    if error:
        return error
    error = check_email_and_username(data["email"], data["username"])
    if error:
        return error
    error = check_user_exists(data["username"])
    if error:
        return error
    try:
        ciphertext = base64.b64decode(data["encrypted_KEK"])
        if not ciphertext:
            return "Invalid encrypted_KEK format"
    except (binascii.Error, ValueError):
        return "Invalid encrypted_KEK format"
    return None


@auth_bp.route("/register", methods=["POST"])
def register() -> tuple:
    """Register a new user"""
    data = request.get_json()

    error = validate_register_data(data)
    if error:
        return handle_error(Exception(error), 400 if error != "Username already exists!" else 409)

    user_id = str(uuid.uuid4())

    new_user = UserLogin(
        user_id,
        data["username"],
        data["email"],
        UserLogin.AuthParams(
            password=data["auth_password"],
            salt=data["auth_salt"],
            p=data["auth_argon2id_params"][1],
            m=data["auth_argon2id_params"][0],
            t=data["auth_argon2id_params"][2],
        ),
    )

    new_kek = UserKEK(
        key_id=str(uuid.uuid4()),
        user_id=user_id,
        kek_params=UserKEK.KEKParams(
            salt=data["salt"],
            iv_kek=data["iv_KEK"],
            encrypted_kek=data["encrypted_KEK"],
            assoc_data_kek="User Key Encryption Key for " + user_id,
            p=data["argon2id_params"][1],
            m=data["argon2id_params"][0],
            t=data["argon2id_params"][2],
            verification_code=data["verification_code"],
            verification_iv=data["verification_iv"],
        ),
    )

    db.session.add(new_user)
    db.session.add(new_kek)
    db.session.commit()

    return jsonify({"message": "User created successfully!", "user_id": user_id}), 201


def validate_retrieve_files_data(data: dict) -> str | None:
    return check_fields(
        data,
        required=["username", "password_derived_key"],
    ) or (
        None
        if isinstance(data["username"], str) and isinstance(data["password_derived_key"], str)
        else "Username and password derived key must be strings"
    )


def get_user_and_kek(username: str) -> tuple[UserLogin | None, UserKEK | None, str | None]:
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
        aesgcm = AESGCM(password_key)
        kek = aesgcm.decrypt(iv_kek, encrypted_kek, None)
    except (binascii.Error, ValueError, AttributeError):
        return "Invalid password!"

    try:
        verification_iv = base64.b64decode(kek_data.verification_iv)
        verification_code = base64.b64decode(kek_data.verification_code)
        aesgcm = AESGCM(kek)
        plaintext = aesgcm.decrypt(verification_iv, verification_code, None)
        if plaintext.decode("utf-8") != "VERIFICATION_SUCCESS":
            return "Invalid password!"
    except (binascii.Error, ValueError, AttributeError):
        return "Invalid password!"

    return None


def decrypt_user_files(user: UserLogin, kek_data: UserKEK, password_derived_key: str) -> list[dict]:
    """Decrypt all files for a user using their password-derived-key and KEK"""
    password_key = base64.b64decode(password_derived_key)
    encrypted_kek = base64.b64decode(kek_data.encrypted_kek)
    iv_kek = base64.b64decode(kek_data.iv_kek)
    aesgcm_kek = AESGCM(password_key)
    kek = aesgcm_kek.decrypt(iv_kek, encrypted_kek, None)

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
        aesgcm_dek = AESGCM(kek)
        dek_bytes = aesgcm_dek.decrypt(iv_dek, encrypted_dek, None)

        iv_file = base64.b64decode(file.iv_file)
        aesgcm_file = AESGCM(dek_bytes)
        try:
            decrypted_content = aesgcm_file.decrypt(iv_file, file.encrypted_file, None)
        except (binascii.Error, ValueError, AttributeError):
            decrypted_content = None

        decrypted_files.append(
            {
                "file_id": file.file_id,
                "file_name": file.file_name,
                "decrypted_content": base64.b64encode(decrypted_content).decode("utf-8") if decrypted_content else None,
                "created_at": file.created_at.isoformat() if hasattr(file, "created_at") else None,
            },
        )
    return decrypted_files


@auth_bp.route("/retrieve-files", methods=["POST"])
def retrieve_files() -> tuple:
    """Retrieve files for a user"""
    data = request.get_json()

    error = validate_retrieve_files_data(data)
    if error:
        return handle_error(Exception(error), 400)

    user, kek_data, error = get_user_and_kek(data["username"])
    if error:
        return handle_error(Exception(error), 404)

    if user is None or kek_data is None:
        return handle_error(Exception("User not found!" if user is None else "User KEK not found!"), 404)

    error = verify_password_and_kek(data["password_derived_key"], kek_data)
    if error:
        return handle_error(Exception(error), 401 if "password" in error else 500)

    jwt_secret = current_app.config["JWT_SECRET_KEY"]
    if jwt_secret is None:
        return handle_error(Exception("JWT secret key is not set in environment variables!"), 500)

    token = jwt.encode(
        {
            "user_id": user.id,
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        },
        jwt_secret,
    )

    decrypted_files = decrypt_user_files(user, kek_data, data["password_derived_key"])

    return jsonify(
        {"token": token, "user_id": user.id, "username": user.username, "files": decrypted_files},
    ), 200


@auth_bp.route("/login", methods=["POST"])
def login() -> tuple:
    """Login a user and return a JWT token"""
    data = request.get_json()

    required_fields = ["username", "entered_auth_password"]
    for field in required_fields:
        if field not in data:
            return handle_error(Exception(f"Missing required field: {field}"), 400)

    user = UserLogin.query.filter_by(username=data["username"]).first()
    if not user:
        return handle_error(Exception("Invalid username!"), 404)

    try:
        ph = PasswordHasher(
            time_cost=user.auth_t,
            memory_cost=user.auth_m,
            parallelism=user.auth_p,
            hash_len=32,
            salt_len=16,
        )
        ph.verify(user.auth_password, data["entered_auth_password"])
    except VerifyMismatchError:
        return handle_error(Exception("Invalid authentication password!"), 401)

    jwt_secret = current_app.config["JWT_SECRET_KEY"]
    if jwt_secret is None:
        return handle_error(Exception("JWT secret key is not set in environment variables!"), 500)

    token = jwt.encode(
        {
            "user_id": user.id,
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        },
        jwt_secret,
    )

    return jsonify({"token": token, "user_id": user.id, "username": user.username}), 200


@auth_bp.route("/auth-password", methods=["PUT"])
@token_required
def change_auth_password() -> tuple:
    """Change the authentication password for a user"""
    data = request.get_json()

    required_fields = [
        "username",
        "old_auth_password",
        "new_auth_password",
        "new_auth_salt",
        "new_auth_argon2id_params",
    ]
    for field in required_fields:
        if field not in data:
            return handle_error(Exception(f"Missing required field: {field}"), 400)

    user = UserLogin.query.filter_by(username=data["username"]).first()
    if not user:
        return handle_error(Exception("Invalid username or user not found!"), 404)

    try:
        ph = PasswordHasher(
            time_cost=user.auth_t,
            memory_cost=user.auth_m,
            parallelism=user.auth_p,
            hash_len=32,
            salt_len=16,
        )
        ph.verify(user.auth_password, data["old_auth_password"])
    except VerifyMismatchError:
        return handle_error(Exception("Invalid old authentication password!"), 401)

    if data["old_auth_password"] == data["new_auth_password"]:
        return handle_error(
            Exception("New authentication password must be different from the old one"),
            400,
        )

    is_valid, error = validate_base64(data["new_auth_salt"], "new_auth_salt")
    if not is_valid:
        result = handle_error(Exception(error), 400)
    else:
        is_valid, error = validate_argon2id_params(data["new_auth_argon2id_params"])
        result = handle_error(Exception(error), 400) if not is_valid else None

    if result:
        return result

    user.auth_password = data["new_auth_password"]
    user.auth_salt = data["new_auth_salt"]
    user.auth_m = data["new_auth_argon2id_params"][0]
    user.auth_p = data["new_auth_argon2id_params"][1]
    user.auth_t = data["new_auth_argon2id_params"][2]

    db.session.commit()

    return jsonify({"message": "Authentication password changed successfully!"}), 200


@auth_bp.route("/encryption-password", methods=["PUT"])
@token_required
def change_encryption_password() -> tuple:
    """Change the encryption password for a user"""
    data = request.get_json()

    error = _validate_encryption_password_fields(data)
    if error:
        return handle_error(Exception(error), 400)

    user = UserLogin.query.filter_by(username=data["username"]).first()
    if not user:
        return handle_error(Exception("User not found!"), 404)
    user_id = user.id

    kek_data = UserKEK.query.filter_by(user_id=user_id).first()
    if not kek_data:
        return handle_error(Exception("User KEK not found!"), 404)

    error = _verify_old_encryption_password(data, kek_data)
    if error:
        code = 401 if "password" in error or "Authentication failed" in error else 400
        return handle_error(Exception(error), code)

    kek_data.salt = data["new_salt"]
    kek_data.iv_KEK = data["new_iv_KEK"]
    kek_data.encrypted_KEK = data["new_encrypted_KEK"]
    kek_data.p = data["new_argon2id_params"][0]
    kek_data.m = data["new_argon2id_params"][1]
    kek_data.t = data["new_argon2id_params"][2]
    kek_data.verification_code = data["new_verification_code"]
    kek_data.verification_iv = data["new_verification_iv"]

    db.session.commit()
    return jsonify({"message": "Encryption password changed successfully!"}), 200


def _validate_encryption_password_fields(data: dict) -> str | None:
    return check_fields(
        data,
        required=[
            "username",
            "old_password_derived_key",
            "new_password_derived_key",
            "new_salt",
            "new_iv_KEK",
            "new_encrypted_KEK",
            "new_verification_code",
            "new_verification_iv",
            "new_argon2id_params",
        ],
        base64_fields=[
            "old_password_derived_key",
            "new_salt",
            "new_iv_KEK",
            "new_encrypted_KEK",
            "new_verification_code",
            "new_verification_iv",
        ],
        iv_fields=["new_iv_KEK", "new_verification_iv"],
        argon2id_fields=["new_argon2id_params"],
    )


def _verify_old_encryption_password(data: dict, kek_data: UserKEK) -> str | None:
    try:
        old_password_key = base64.b64decode(data["old_password_derived_key"])
        encrypted_kek = base64.b64decode(kek_data.encrypted_kek)
        iv_kek = base64.b64decode(kek_data.iv_kek)
        try:
            aesgcm = AESGCM(old_password_key)
            old_kek = aesgcm.decrypt(iv_kek, encrypted_kek, None)
        except (binascii.Error, ValueError, AttributeError):
            return "Invalid old password!"

        verification_iv = base64.b64decode(kek_data.verification_iv)
        verification_code = base64.b64decode(kek_data.verification_code)
        try:
            aesgcm = AESGCM(old_kek)
            plaintext = aesgcm.decrypt(verification_iv, verification_code, None)
            if plaintext.decode("utf-8") != "VERIFICATION_SUCCESS":
                return "Invalid old password!"
        except (binascii.Error, ValueError, AttributeError):
            return "Invalid old password!"
    except (binascii.Error, ValueError, AttributeError) as e:
        return "Authentication failed: " + str(e)
    return None


@auth_bp.route("/<user_id>", methods=["DELETE"])
def delete_user(user_id: str) -> tuple:
    """Delete a user and their KEK after verifying password"""
    data = request.get_json()
    if not data or "password" not in data:
        return handle_error(Exception("Missing required field: password"), 400)

    user = UserLogin.query.filter_by(id=user_id).first()
    if not user:
        return handle_error(Exception("User not found!"), 404)

    try:
        ph = PasswordHasher(
            time_cost=user.auth_t,
            memory_cost=user.auth_m,
            parallelism=user.auth_p,
            hash_len=32,
            salt_len=16,
        )
        ph.verify(user.auth_password, data["password"])
    except VerifyMismatchError:
        return handle_error(Exception("Invalid password!"), 401)

    kek = UserKEK.query.filter_by(user_id=user_id).first()
    if kek:
        db.session.delete(kek)
    db.session.delete(user)
    db.session.commit()

    return jsonify({"message": "User deleted successfully!"}), 200


@auth_bp.route("/user-id", methods=["POST"])
def get_user_id() -> tuple:
    """Return the user_id for a given username"""
    data = request.get_json()
    if not data or "username" not in data:
        return handle_error(Exception("Missing required field: username"), 400)

    user = UserLogin.query.filter_by(username=data["username"]).first()
    if not user:
        return handle_error(Exception("User not found!"), 404)

    return jsonify({"user_id": user.id}), 200
