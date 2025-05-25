import base64  # noqa: INP001
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import current_app, jsonify, request
from flask_restx import Namespace, Resource, fields

from app import db
from app.models.file import File, FileDEK
from app.models.share import FileShare
from app.models.user import UserKEK, UserLogin
from app.utils.token import token_required

shares_ns = Namespace("shares", description="Share management")

file_dek_model = shares_ns.model(
    "FileDEK",
    {
        "key_id": fields.String,
        "iv_dek": fields.String(description="Base64-encoded IV for DEK"),
        "encrypted_dek": fields.String(description="Base64-encoded encrypted DEK"),
        "assoc_data_dek": fields.String(description="Associated data for DEK"),
    },
)

file_model = shares_ns.model(
    "File",
    {
        "file_id": fields.String(description="Unique identifier for the file"),
        "file_name": fields.String(description="Name of the file"),
        "file_type": fields.String(description="MIME type of the file"),
        "file_size": fields.Integer(description="Size of the file in bytes"),
        "iv_file": fields.String(description="Base64-encoded IV for file"),
        "created_at": fields.String(description="Creation timestamp of the file", example="2023-10-01T12:00:00Z"),
        "dek_data": fields.Nested(file_dek_model, allow_null=True),
    },
)

files_list_model = shares_ns.model(
    "FilesList",
    {
        "files": fields.List(fields.Nested(file_model)),
        "count": fields.Integer(description="Total number of files owned by the user"),
    },
)

share_request_model = shares_ns.model(
    "ShareRequest",
    {
        "shared_with_username": fields.String(required=True, description="Username of the recipient"),
        "encrypted_dek": fields.String(required=True, description="Base64-encoded DEK encrypted for recipient"),
        "iv_dek": fields.String(required=True, description="Base64-encoded IV for DEK"),
        "assoc_data_dek": fields.String(required=True, description="Associated data for DEK"),
        "password-derived-key": fields.String(
            required=True,
            description="Base64-encoded password-derived key used to encrypt the DEK",
        ),
    },
)

share_response_model = shares_ns.model(
    "ShareResponse",
    {
        "message": fields.String(description="Success message after sharing the file"),
        "share_id": fields.String(description="The ID of the share"),
        "shared_with": fields.String(description="The ID of the user the file was shared with"),
    },
)

share_list_model = shares_ns.model(
    "ShareList",
    {
        "shares": fields.List(
            fields.Nested(
                shares_ns.model(
                    "ShareInfo",
                    {
                        "share_id": fields.String(description="Unique identifier for the share"),
                        "shared_with": fields.String(description="ID of the user the file is shared with"),
                        "shared_with_username": fields.String(description="Username of the recipient"),
                        "created_at": fields.String(
                            description="Creation timestamp of the share",
                            example="2023-10-01T12:00:00Z",
                        ),
                        "file_id": fields.String(description="ID of the shared file"),
                        "file_name": fields.String(description="Name of the shared file"),
                        "file_size": fields.Integer(description="Size of the shared file in bytes"),
                        "file_type": fields.String(description="MIME type of the shared file"),
                        "encrypted_dek": fields.String(description="Base64-encoded DEK encrypted for recipient"),
                        "iv_dek": fields.String(description="Base64-encoded IV for DEK"),
                        "assoc_data_dek": fields.String(description="Associated data for DEK"),
                    },
                ),
            ),
        ),
        "count": fields.Integer(description="Total number of shares for the file"),
    },
)

revoke_request_model = shares_ns.model(
    "RevokeRequest",
    {
        "shared_with_username": fields.String(required=True, description="Username of the recipient to revoke"),
    },
)


def pull_info_for_share(file_id: str, user_id: str, shared_with: str) -> tuple:
    """Pull file and DEK info for sharing"""
    file = File.query.filter_by(file_id=file_id, created_by=user_id).first()
    if not file:
        return None, None, (jsonify({"message": "File not found or access denied"}), 404), None

    recipient = UserLogin.query.filter_by(username=shared_with).first()
    if not recipient:
        return None, None, (jsonify({"message": "Recipient user not found"}), 404), None
    if recipient.id == user_id:
        return None, None, (jsonify({"message": "Cannot share file with yourself"}), 400), None

    existing = FileShare.query.filter_by(file_id=file_id, shared_with=recipient.id).first()
    if existing:
        return None, None, (jsonify({"message": "File already shared with this user"}), 400), None

    key = UserKEK.query.filter_by(user_id=recipient.id).first()
    if not key:
        return None, None, (jsonify({"message": "Recipient does not have a valid KEK"}), 404), None

    return file, key, None, recipient


def verify_shared_data(data: dict) -> tuple:
    """Verify the shared data for required fields"""
    shared_with_username = data.get("shared_with_username")
    pdk = data.get("password-derived-key")
    if not shared_with_username:
        return None, None, (jsonify({"message": "Missing recipient username"}), 400)
    if not pdk:
        return None, None, (jsonify({"message": "Missing password-derived key"}), 400)
    return shared_with_username, pdk, None


@shares_ns.route("/<file_id>/share")
@shares_ns.param("file_id", "The file identifier")
class FileShareResource(Resource):
    @shares_ns.doc(security="apikey")
    @shares_ns.expect(share_request_model)
    @shares_ns.response(201, "File shared successfully", share_response_model)
    @shares_ns.response(404, "File or recipient not found")
    @shares_ns.response(403, "Access denied")
    @token_required
    def post(self, current_user: UserLogin, file_id: str) -> tuple:
        """Share a file with another user (by username) and re-encrypt DEK with recipient's public key"""

        data = request.get_json()
        shared_with_username, pdk, error_response = verify_shared_data(data)
        if error_response:
            return error_response

        file, key, error_response, recipient = pull_info_for_share(file_id, current_user.id, shared_with_username)
        if error_response:
            return error_response

        encrypted_kek = base64.b64decode(key.encrypted_kek)
        kek_iv = base64.b64decode(key.kek_iv)
        aesgcm = AESGCM(pdk)
        kek = aesgcm.decrypt(kek_iv, encrypted_kek, None)

        file_dek = FileDEK.query.filter_by(file_id=file_id).first()
        if not file_dek:
            return jsonify({"message": "File DEK not found"}), 404
        dek_iv = base64.b64decode(file_dek.iv_dek)
        share_encryped_dek = base64.b64decode(file_dek.encrypted_dek)
        aesgcm_kek = AESGCM(kek)
        dek = aesgcm_kek.decrypt(dek_iv, share_encryped_dek, file_dek.assoc_data_dek.encode())

        recipient_public_key = serialization.load_pem_public_key(
            key.public_key.encode("utf-8"),
        )

        if not isinstance(recipient_public_key, ed25519.Ed25519PublicKey):
            return jsonify(
                {
                    "message": ("Recipient's public key is not an Ed25519 key and cannot be used for encryption"),
                },
            ), 400

        try:
            recipient_x25519_pub = x25519.X25519PublicKey.from_public_bytes(
                recipient_public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                ),
            )
        except (ValueError, TypeError):
            return jsonify({"message": "Failed to convert Ed25519 public key to X25519 for encryption"}), 400

        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()

        shared_secret = ephemeral_private.exchange(recipient_x25519_pub)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"file-share-ed25519",
        )
        symmetric_key = hkdf.derive(shared_secret)

        aesgcm = AESGCM(symmetric_key)
        iv = AESGCM.generate_key(bit_length=96)
        encrypted_dek = aesgcm.encrypt(iv, dek, None)

        share = FileShare(
            share_id=str(uuid.uuid4()),
            file_id=file_id,
            shared_with=recipient.id,
            encrypted_dek=base64.b64encode(encrypted_dek),
            iv_dek=base64.b64encode(iv).decode(),
            assoc_data_dek=base64.b64encode(
                ephemeral_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                ),
            ).decode(),
        )
        db.session.add(share)
        db.session.commit()
        return {
            "message": "File shared successfully",
            "share_id": share.share_id,
            "shared_with": recipient.id,
        }, 201

    @shares_ns.doc(security="apikey")
    @shares_ns.marshal_with(share_list_model)
    @token_required
    def get(self, current_user: UserLogin, file_id: str) -> tuple:
        """List users this file is shared with, including file info"""
        file = File.query.filter_by(file_id=file_id, created_by=current_user.id).first()
        if not file:
            return {"shares": [], "count": 0}, 404
        shares = FileShare.query.filter_by(file_id=file.file_id).all()
        share_list = [
            {
                "share_id": s.share_id,
                "shared_with": s.shared_with,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "file_id": file.file_id,
                "file_name": file.file_name,
                "file_size": file.file_size,
                "file_type": file.file_type,
                "encrypted_dek": s.encrypted_dek,
                "iv_dek": s.iv_dek,
                "assoc_data_dek": s.assoc_data_dek,
            }
            for s in shares
        ]
        return {"shares": share_list, "count": len(share_list)}, 200

    @shares_ns.doc(security="apikey")
    @shares_ns.expect(revoke_request_model)
    @shares_ns.response(200, "Access revoked")
    @shares_ns.response(404, "File or share not found")
    @token_required
    def delete(self, current_user: UserLogin, file_id: str) -> tuple:
        """Revoke a user's access to a shared file"""
        data = request.get_json()
        file = File.query.filter_by(file_id=file_id, created_by=current_user.id).first()
        if not file:
            return jsonify({"message": "File not found or access denied"}), 404
        recipient = UserLogin.query.filter_by(username=data.get("shared_with_username")).first()
        if not recipient:
            return jsonify({"message": "Recipient user not found"}), 404
        share = FileShare.query.filter_by(file_id=file_id, shared_with=recipient.id).first()
        if not share:
            return jsonify({"message": "Share not found"}), 404
        db.session.delete(share)
        db.session.commit()
        return {"message": "Access revoked"}, 200


@shares_ns.route("/shared-with-me/<user_id>")
@shares_ns.param("user_id", "The user identifier")
class FilesSharedWithMe(Resource):
    @shares_ns.doc(security="apikey")
    @shares_ns.marshal_with(files_list_model)
    @token_required
    def get(self, current_user: UserLogin) -> tuple:
        """Get all files shared with the specified user"""
        try:
            shares = FileShare.query.filter_by(shared_with=current_user.id).all()
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
                        "assoc_data_file": file.assoc_data_file,
                        "created_at": file.created_at.isoformat(),
                        "file_size": file.file_size,
                    },
                )
            return {"files": files_data, "count": len(files_data)}, 200
        except db.exc.SQLAlchemyError:
            current_app.logger.exception("Database error retrieving shared files")
            return {"files": [], "count": 0}, 500
