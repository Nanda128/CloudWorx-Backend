from flask_restx import Namespace, fields  # noqa: INP001


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
            "file_id": fields.String(description="File ID"),
            "file_name": fields.String(description="File name"),
            "file_type": fields.String(description="File type/extension"),
            "assoc_data_file": fields.String(description="Associated data for file"),
            "created_at": fields.String(description="File creation timestamp"),
            "file_size": fields.Integer(description="File size in bytes"),
        },
    )

    share_info_model = shares_ns.model(
        "ShareInfo",
        {
            "share_id": fields.String(description="Share ID"),
            "shared_with": fields.String(description="User ID of recipient"),
            "created_at": fields.String(description="Share creation timestamp"),
            "file_id": fields.String(description="File ID"),
            "file_name": fields.String(description="File name"),
            "file_size": fields.Integer(description="File size in bytes"),
            "file_type": fields.String(description="File type/extension"),
            "encrypted_dek": fields.String(description="Encrypted data encryption key"),
            "iv_dek": fields.String(description="Initialization vector for DEK"),
            "assoc_data_dek": fields.String(description="Associated data for DEK"),
        },
    )

    return {
        "share_request_model": shares_ns.model(
            "ShareRequest",
            {
                "shared_with_username": fields.String(required=True, description="Username to share with"),
                "password-derived-key": fields.String(required=True, description="Password-derived key for encryption"),
            },
        ),
        "share_response_model": shares_ns.model(
            "ShareResponse",
            {
                "message": fields.String(description="Status message"),
                "share_id": fields.String(description="Share ID"),
                "shared_with": fields.String(description="User ID of recipient"),
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
    }
