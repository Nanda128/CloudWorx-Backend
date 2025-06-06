from flask_restx import Namespace, fields


def register_auth_models(auth_ns: Namespace) -> dict:
    """Register models for auth-related API endpoints"""

    auth_ns.authorizations = {
        "apikey": {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "JWT token in format: Bearer <token>",
        },
    }

    user_file_info_model = auth_ns.model(
        "UserFileInfo",
        {
            "file_id": fields.String(description="File ID"),
            "file_name": fields.String(description="File name"),
            "file_type": fields.String(description="File type/extension"),
            "file_size": fields.Integer(description="File size in bytes"),
        },
    )

    return {
        "register_model": auth_ns.model(
            "Register",
            {
                "username": fields.String(required=True),
                "auth_password": fields.String(
                    required=True,
                    description="Authentication password",
                ),
                "email": fields.String(required=True),
                "public_key": fields.String(
                    required=True,
                    description="Base64-encoded X25519 public key for encryption",
                ),
                "signing_public_key": fields.String(
                    required=True,
                    description="Base64-encoded Ed25519 public key for signing",
                ),
                "iv_KEK": fields.String(
                    required=True,
                    description="Base64-encoded IV",
                ),
                "salt": fields.String(
                    required=True,
                    description="Salt for password hashing",
                ),
                "p": fields.Integer(
                    required=True,
                    description="Argon2id parameter p",
                ),
                "m": fields.Integer(
                    required=True,
                    description="Argon2id parameter m",
                ),
                "t": fields.Integer(
                    required=True,
                    description="Argon2id parameter t",
                ),
                "encrypted_KEK": fields.String(
                    required=True,
                    description="Base64-encoded KEK",
                ),
            },
        ),
        "register_response_model": auth_ns.model(
            "RegisterResponse",
            {
                "message": fields.String(description="Success message"),
                "user_id": fields.String(description="Generated user ID"),
                "key_fingerprint": fields.String(description="Public key fingerprint"),
                "tofu_message": fields.String(description="TOFU verification message"),
                "token": fields.String(description="JWT authentication token"),
            },
        ),
        "login_model": auth_ns.model(
            "Login",
            {
                "username": fields.String(required=True),
                "entered_auth_password": fields.String(
                    required=True,
                    description="Authentication password (must be plaintext)",
                ),
            },
        ),
        "change_auth_password_model": auth_ns.model(
            "ChangeAuthPassword",
            {
                "old_auth_password": fields.String(
                    required=True,
                    description="Old authentication password (must not be hashed)",
                ),
                "new_auth_password": fields.String(
                    required=True,
                    description="New authentication password (must be hashed with Argon2id before sending)",
                ),
            },
        ),
        "change_encryption_password_model": auth_ns.model(
            "ChangeEncryptionPassword",
            {
                "old_password_derived_key": fields.String(
                    required=True,
                    description="Argon2ID hash of the old password",
                ),
                "new_iv_KEK": fields.String(
                    required=True,
                    description="Base64-encoded IV for new KEK",
                ),
                "new_encrypted_KEK": fields.String(
                    required=True,
                    description="Base64-encoded encrypted KEK with new password",
                ),
            },
        ),
        "delete_user_model": auth_ns.model(
            "DeleteUser",
            {
                "password": fields.String(
                    required=True,
                    description="User's authentication password (must be plaintext)",
                ),
            },
        ),
        "user_file_info_model": user_file_info_model,
        "login_info_model": auth_ns.model(
            "LoginResponse",
            {
                "token": fields.String(description="JWT token"),
                "user_id": fields.String(description="User ID"),
            },
        ),
        "get_all_users_response_model": auth_ns.model(
            "GetAllUsersResponse",
            {
                "users": fields.List(
                    fields.Nested(
                        auth_ns.model(
                            "UserBasicInfo",
                            {
                                "username": fields.String(description="Username"),
                                "email": fields.String(description="User email"),
                            },
                        ),
                    ),
                    description="List of all users with username and email",
                ),
            },
        ),
        "get_user_info_response_model": auth_ns.model(
            "GetUserInfoResponse",
            {
                "user_id": fields.String(description="User ID"),
                "username": fields.String(description="Username"),
                "email": fields.String(description="User email"),
                "public_key": fields.String(description="Base64-encoded public key"),
                "created_at": fields.String(description="ISO8601 user creation timestamp"),
                "modified_at": fields.String(description="ISO8601 user modification timestamp"),
                "key_id": fields.String(description="KEK key ID", required=False),
                "iv_KEK": fields.String(description="Base64-encoded IV for KEK", required=False),
                "encrypted_KEK": fields.String(description="Base64-encoded encrypted KEK", required=False),
                "assoc_data_KEK": fields.String(description="Associated data for KEK", required=False),
                "salt": fields.String(description="Base64-encoded salt for password hashing", required=False),
                "p": fields.Integer(description="Argon2id parameter p", required=False),
                "m": fields.Integer(description="Argon2id parameter m", required=False),
                "t": fields.Integer(description="Argon2id parameter t", required=False),
                "kek_created_at": fields.String(description="ISO8601 KEK creation timestamp", required=False),
            },
        ),
        "get_username_by_id_response_model": auth_ns.model(
            "GetUsernameByIdResponse",
            {
                "username": fields.String(description="Username of the user"),
            },
        ),
    }
