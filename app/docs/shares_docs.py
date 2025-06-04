from flask_restx import Namespace, fields


def register_shares_models(shares_ns: Namespace) -> dict:
    """Register models for share-related API endpoints"""

    shares_ns.authorizations = {
        "apikey": {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "JWT token in format: Bearer <token>",
        },
    }

    shared_file_model = shares_ns.model(
        "SharedFileInfo",
        {
            "share_id": fields.String(description="Share ID"),
            "file_id": fields.String(description="File ID"),
            "file_name": fields.String(description="File name"),
            "file_type": fields.String(description="File type/extension"),
            "file_size": fields.Integer(description="File size in bytes"),
            "shared_by": fields.String(description="User ID who shared the file"),
            "shared_by_username": fields.String(description="Username who shared the file"),
            "created_at": fields.String(description="Share creation timestamp"),
        },
    )

    share_info_model = shares_ns.model(
        "ShareInfo",
        {
            "share_id": fields.String(description="Share ID"),
            "shared_with": fields.String(description="User ID of recipient"),
            "shared_with_username": fields.String(description="Username of recipient"),
            "created_at": fields.String(description="Share creation timestamp"),
            "file_id": fields.String(description="File ID"),
            "file_name": fields.String(description="File name"),
            "file_size": fields.Integer(description="File size in bytes"),
            "file_type": fields.String(description="File type/extension"),
        },
    )

    public_key_model = shares_ns.model(
        "PublicKeyResponse",
        {
            "username": fields.String(description="Username"),
            "user_id": fields.String(description="User ID"),
            "x25519_public_key": fields.String(description="X25519 public key in PEM format"),
            "ed25519_public_key": fields.String(description="Ed25519 public key in PEM format"),
            "tofu_message": fields.String(description="TOFU verification message"),
        },
    )

    return {
        "share_request_model": shares_ns.model(
            "ShareRequest",
            {
                "shared_with_username": fields.String(required=True, description="Username to share with"),
                "encrypted_file": fields.String(required=True, description="Base64-encoded encrypted file data"),
                "nonce": fields.String(required=True, description="Base64-encoded AES-GCM nonce"),
                "ephemeral_public_key": fields.String(
                    required=True, description="Base64-encoded ephemeral X25519 public key",
                ),
                "signature": fields.String(required=True, description="Base64-encoded Ed25519 signature"),
            },
        ),
        "download_response_model": shares_ns.model(
            "DownloadResponse",
            {
                "file_id": fields.String(description="File ID"),
                "file_name": fields.String(description="File name"),
                "file_type": fields.String(description="File type"),
                "file_size": fields.Integer(description="File size in bytes"),
                "shared_by": fields.String(description="Sender user ID"),
                "shared_by_username": fields.String(description="Sender username"),
                "encrypted_file": fields.String(description="Base64-encoded encrypted file data"),
                "nonce": fields.String(description="Base64-encoded AES-GCM nonce"),
                "ephemeral_public_key": fields.String(description="Base64-encoded ephemeral X25519 public key"),
                "sender_signature": fields.String(description="Base64-encoded Ed25519 signature"),
                "sender_x25519_public_key": fields.String(description="Sender's X25519 public key in PEM format"),
                "sender_ed25519_public_key": fields.String(description="Sender's Ed25519 public key in PEM format"),
                "created_at": fields.String(description="Share creation timestamp"),
            },
        ),
        "share_response_model": shares_ns.model(
            "ShareResponse",
            {
                "message": fields.String(description="Status message"),
                "share_id": fields.String(description="Share ID"),
                "shared_with": fields.String(description="User ID of recipient"),
                "tofu_message": fields.String(description="TOFU verification message"),
            },
        ),
        "share_list_model": shares_ns.model(
            "SharesList",
            {
                "shares": fields.List(fields.Nested(share_info_model)),
                "count": fields.Integer(description="Total number of shares"),
            },
        ),
        "revoke_request_model": shares_ns.model(
            "RevokeRequest",
            {
                "shared_with_username": fields.String(required=True, description="Username to revoke share from"),
            },
        ),
        "revoke_response_model": shares_ns.model(
            "RevokeResponse",
            {
                "message": fields.String(description="Status message"),
            },
        ),
        "files_list_model": shares_ns.model(
            "SharedFilesList",
            {
                "files": fields.List(fields.Nested(shared_file_model)),
                "count": fields.Integer(description="Total number of shared files"),
            },
        ),
        "public_key_model": public_key_model,
    }
