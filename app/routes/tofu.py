from flask import request
from flask_restx import Namespace, Resource

from app.docs.tofu_docs import register_tofu_models
from app.models.tofu import TrustedKey
from app.models.user import UserLogin
from app.utils.tofu import revoke_user_key
from app.utils.token import token_required

tofu_ns = Namespace("tofu", description="TOFU key management")

models = register_tofu_models(tofu_ns)


@tofu_ns.route("/keys")
class TrustedKeysList(Resource):
    @tofu_ns.doc(security="apikey")
    @tofu_ns.response(200, "Trusted keys retrieved successfully", models["trusted_keys_list_model"])
    @token_required
    def get(self, current_user: UserLogin) -> tuple:
        """Get all trusted keys for the current user"""
        keys = TrustedKey.query.filter_by(user_id=current_user.id).all()

        keys_data = [
            {
                "id": key.id,
                "key_fingerprint": key.key_fingerprint,
                "first_seen": key.first_seen.isoformat() if key.first_seen else None,
                "last_verified": key.last_verified.isoformat() if key.last_verified else None,
                "trust_status": key.trust_status.value,
                "verification_count": key.verification_count,
            }
            for key in keys
        ]

        return {"keys": keys_data, "count": len(keys_data)}, 200


@tofu_ns.route("/keys/<key_fingerprint>/revoke")
class RevokeKey(Resource):
    @tofu_ns.doc(security="apikey")
    @tofu_ns.response(200, "Key revoked successfully")
    @tofu_ns.response(404, "Key not found")
    @token_required
    def post(self, current_user: UserLogin, key_fingerprint: str) -> tuple:
        """Revoke a trusted key"""
        if revoke_user_key(current_user.id, key_fingerprint):
            return {"message": "Key revoked successfully"}, 200
        return {"message": "Key not found"}, 404


@tofu_ns.route("/verify")
class VerifyKey(Resource):
    @tofu_ns.doc(security="apikey")
    @tofu_ns.expect(models["verify_key_request_model"])
    @tofu_ns.response(200, "Key verification result", models["verify_key_response_model"])
    @token_required
    def post(self, current_user: UserLogin) -> tuple:
        """Manually verify a public key"""
        from app.utils.tofu import verify_tofu_key

        data = request.get_json()
        public_key = data.get("public_key")

        if not public_key:
            return {"message": "Missing public key"}, 400

        is_trusted, message, trusted_key = verify_tofu_key(current_user.id, public_key)

        result = {
            "is_trusted": is_trusted,
            "message": message,
        }

        if trusted_key:
            result["key_fingerprint"] = trusted_key.key_fingerprint
            result["trust_status"] = trusted_key.trust_status.value

        return result, 200
