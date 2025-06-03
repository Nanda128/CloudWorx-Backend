from flask_restx import Namespace, fields


def register_tofu_models(tofu_ns: Namespace) -> dict:
    """Register models for TOFU-related API endpoints"""

    tofu_ns.authorizations = {
        "apikey": {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "JWT token in format: Bearer <token>",
        },
    }

    trusted_key_model = tofu_ns.model(
        "TrustedKey",
        {
            "id": fields.String(description="Key ID"),
            "key_fingerprint": fields.String(description="SHA256 fingerprint"),
            "first_seen": fields.String(description="First seen timestamp"),
            "last_verified": fields.String(description="Last verified timestamp"),
            "trust_status": fields.String(description="Trust status"),
            "verification_count": fields.Integer(description="Number of verifications"),
        },
    )

    return {
        "trusted_key_model": trusted_key_model,
        "trusted_keys_list_model": tofu_ns.model(
            "TrustedKeysList",
            {
                "keys": fields.List(fields.Nested(trusted_key_model)),
                "count": fields.Integer(description="Total number of trusted keys"),
            },
        ),
        "verify_key_request_model": tofu_ns.model(
            "VerifyKeyRequest",
            {
                "public_key": fields.String(required=True, description="Base64-encoded public key"),
            },
        ),
        "verify_key_response_model": tofu_ns.model(
            "VerifyKeyResponse",
            {
                "is_trusted": fields.Boolean(description="Whether the key is trusted"),
                "message": fields.String(description="Verification message"),
                "key_fingerprint": fields.String(description="SHA256 fingerprint", required=False),
                "trust_status": fields.String(description="Trust status", required=False),
            },
        ),
    }
