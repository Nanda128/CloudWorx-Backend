from __future__ import annotations

import base64
import binascii
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from flask import current_app, request
from flask_restx import Namespace, Resource

from app import db
from app.docs.shares_docs import register_shares_models
from app.models.file import File
from app.models.share import FileShare
from app.models.user import UserLogin
from app.utils.tofu import verify_tofu_key
from app.utils.token import token_required

shares_ns = Namespace("shares", description="Share management")

models = register_shares_models(shares_ns)

EPHEMERAL_PUBLIC_KEY_LENGTH = 32
ED25519_SIGNATURE_LENGTH = 64


@shares_ns.route("/public-key/<username>")
@shares_ns.param("username", "The username to get public key for")
class PublicKeyResource(Resource):
    @shares_ns.doc(security="apikey")
    @shares_ns.response(200, "Public key retrieved successfully", models["public_key_model"])
    @shares_ns.response(404, "User not found")
    @token_required
    def get(self, _current_user: UserLogin, username: str) -> tuple:
        """Get another user's X25519 and Ed25519 public keys for sharing"""
        user = UserLogin.query.filter_by(username=username).first()
        if not user:
            current_app.logger.warning("User %s not found for public key request", username)
            return {"message": "User not found"}, 404

        try:
            x25519_key = serialization.load_pem_public_key(user.public_key.encode("utf-8"))
            if not isinstance(x25519_key, x25519.X25519PublicKey):
                current_app.logger.warning("User %s does not have a valid X25519 public key", username)
                return {"message": "User does not have a valid X25519 public key"}, 400

            ed25519_key = serialization.load_pem_public_key(user.signing_public_key.encode("utf-8"))
            if not isinstance(ed25519_key, ed25519.Ed25519PublicKey):
                current_app.logger.warning("User %s does not have a valid Ed25519 signing key", username)
                return {"message": "User does not have a valid Ed25519 signing key"}, 400
        except (ValueError, TypeError):
            current_app.logger.warning("Invalid public key format for user %s", username)
            return {"message": "User has invalid public key format"}, 400

        try:
            is_trusted, tofu_message, _ = verify_tofu_key(user.id, user.public_key)
            if not is_trusted:
                current_app.logger.warning("TOFU verification failed for public key request: %s", tofu_message)
                return {"message": f"Key verification failed: {tofu_message}"}, 400
        except (LookupError, ValueError) as e:
            current_app.logger.warning("Database enum error during TOFU verification for user %s: %s", username, str(e))
            tofu_message = "Key verification temporarily unavailable - proceeding with caution"
        except Exception:
            current_app.logger.exception("Unexpected error during TOFU verification for user %s", username)
            return {"message": "Key verification service temporarily unavailable"}, 503

        return {
            "username": user.username,
            "user_id": user.id,
            "x25519_public_key": user.public_key,
            "ed25519_public_key": user.signing_public_key,
            "tofu_message": tofu_message,
        }, 200


def validate_base64_data(data: str, field_name: str) -> tuple[bool, str, bytes | None]:
    """Validate and decode base64 data, returning success status, error message, and decoded data"""
    try:
        if not data.replace("=", "").replace("+", "").replace("/", "").isalnum():
            return False, f"Invalid characters in {field_name} - must be valid base64", None

        decoded_data = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as e:
        current_app.logger.warning("Base64 validation failed for %s: %s", field_name, str(e))
        return False, f"Invalid base64 encoding for {field_name}: {e!s}", None
    else:
        return True, "", decoded_data


@shares_ns.route("/<file_id>/share")
@shares_ns.param("file_id", "The file identifier")
class FileShareResource(Resource):
    @shares_ns.doc(security="apikey")
    @shares_ns.expect(models["share_request_model"])
    @shares_ns.response(201, "File shared successfully", models["share_response_model"])
    @shares_ns.response(404, "File or recipient not found")
    @shares_ns.response(400, "Validation error")
    @token_required
    def post(self, current_user: UserLogin, file_id: str) -> tuple:
        """Store encrypted file share with cryptographic artifacts provided by client"""
        data = request.get_json()

        validation_result = self.validate_share_request(data)
        if validation_result is not None:
            return validation_result

        (
            shared_with_username,
            encrypted_file_base64,
            nonce_base64,
            ephemeral_public_key_base64,
            signature_base64,
        ) = (
            data["shared_with_username"],
            data["encrypted_file"],
            data["nonce"],
            data["ephemeral_public_key"],
            data["signature"],
        )

        result = self.get_file_and_recipient(
            current_user,
            file_id,
            shared_with_username,
        )
        if result is None:
            return {"message": "Internal error retrieving file or recipient"}, 500
        file, recipient, tofu_message, error_response = result
        if error_response:
            return error_response

        # Validate and decode all base64 fields
        base64_fields = [
            ("encrypted_file", encrypted_file_base64),
            ("nonce", nonce_base64),
            ("ephemeral_public_key", ephemeral_public_key_base64),
            ("signature", signature_base64),
        ]

        decoded_data = {}
        for field_name, field_data in base64_fields:
            is_valid, error_msg, decoded = validate_base64_data(field_data, field_name)
            if not is_valid:
                current_app.logger.warning("Base64 validation failed for %s: %s", field_name, error_msg)
                return {"message": error_msg}, 400
            decoded_data[field_name] = decoded

        try:
            encrypted_file_data = decoded_data["encrypted_file"]
            nonce_data = decoded_data["nonce"]
            ephemeral_public_key_data = decoded_data["ephemeral_public_key"]
            signature_data = decoded_data["signature"]

            if len(ephemeral_public_key_data) != EPHEMERAL_PUBLIC_KEY_LENGTH:
                current_app.logger.warning(
                    "Invalid ephemeral public key length: %d bytes",
                    len(ephemeral_public_key_data),
                )
                return {"message": "Invalid ephemeral public key length"}, 400
            if len(signature_data) != ED25519_SIGNATURE_LENGTH:
                current_app.logger.warning(
                    "Invalid signature length: %d bytes",
                    len(signature_data),
                )
                return {"message": "Invalid signature length"}, 400

            share = FileShare(
                id=str(uuid.uuid4()),
                file_id=file.file_id,
                shared_by=current_user.id,
                shared_with=recipient.id,
                file_name=file.file_name,
                file_type=file.file_type,
                file_size=file.file_size,
                encrypted_file=encrypted_file_data,
                nonce=nonce_data,
                ephemeral_public_key=ephemeral_public_key_data,
                sender_signature=signature_data,
            )

            db.session.add(share)
            db.session.commit()

            current_app.logger.info(
                "File %s shared successfully from user %s to user %s",
                file.file_name,
                current_user.username,
                recipient.username,
            )

        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("Error storing file share")
            return {"message": f"Error sharing file: {e!s}"}, 500
        else:
            return {
                "message": "File shared successfully",
                "share_id": share.id,
                "shared_with": recipient.id,
                "tofu_message": tofu_message,
            }, 201

    def get_file_and_recipient(
        self,
        current_user: UserLogin,
        file_id: str,
        shared_with_username: str,
    ) -> tuple | None:
        file = File.query.filter_by(file_id=file_id, created_by=current_user.id).first()
        if not file:
            current_app.logger.warning(
                "File with ID %s not found or access denied for user %s",
                file_id,
                current_user.username,
            )
            return None, None, None, ({"message": "File not found or access denied"}, 404)

        recipient = UserLogin.query.filter_by(username=shared_with_username).first()
        if not recipient:
            current_app.logger.warning(
                "Recipient user %s not found for sharing file %s",
                shared_with_username,
                file.file_name,
            )
            return None, None, None, ({"message": "Recipient user not found"}, 404)

        if recipient.id == current_user.id:
            current_app.logger.warning(
                "User %s attempted to share file %s with themselves",
                current_user.username,
                file.file_name,
            )
            return None, None, None, ({"message": "Cannot share file with yourself"}, 400)

        existing_share = FileShare.query.filter_by(file_id=file_id, shared_with=recipient.id).first()
        if existing_share:
            current_app.logger.warning(
                "File %s already shared with user %s",
                file.file_name,
                recipient.username,
            )
            return None, None, None, ({"message": "File already shared with this user"}, 400)

        is_trusted, tofu_message, _ = verify_tofu_key(recipient.id, recipient.public_key)
        if not is_trusted:
            current_app.logger.warning(
                "TOFU verification failed for recipient %s: %s",
                recipient.username,
                tofu_message,
            )
            return None, None, None, ({"message": f"Key verification failed: {tofu_message}"}, 400)

        try:
            is_trusted, tofu_message, _ = verify_tofu_key(recipient.id, recipient.public_key)
            if not is_trusted:
                current_app.logger.warning(
                    "TOFU verification failed for recipient %s: %s",
                    recipient.username,
                    tofu_message,
                )
                return None, None, None, ({"message": f"Key verification failed: {tofu_message}"}, 400)
        except (LookupError, ValueError) as e:
            current_app.logger.warning(
                "Database enum error during TOFU verification for recipient %s: %s",
                recipient.username,
                str(e),
            )
            tofu_message = "Key verification temporarily unavailable - proceeding with caution"
        except Exception:
            current_app.logger.exception(
                "Unexpected error during TOFU verification for recipient %s",
                recipient.username,
            )
            return None, None, None, ({"message": "Key verification service temporarily unavailable"}, 503)

        return file, recipient, tofu_message, None

    def validate_share_request(self, data: dict) -> tuple | None:
        required_fields = [
            "shared_with_username",
            "encrypted_file",
            "nonce",
            "ephemeral_public_key",
            "signature",
        ]
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            current_app.logger.warning(
                "Missing required fields for file share: %s",
                ", ".join(missing_fields),
            )
            return {
                "message": (
                    "Missing required fields: shared_with_username, encrypted_file, "
                    "nonce, ephemeral_public_key, signature"
                ),
            }, 400
        return None

    @shares_ns.doc(security="apikey")
    @shares_ns.response(200, "List of shares retrieved successfully", models["share_list_model"])
    @token_required
    def get(self, current_user: UserLogin, file_id: str) -> tuple:
        """List users this file is shared with"""
        file = File.query.filter_by(file_id=file_id, created_by=current_user.id).first()
        if not file:
            current_app.logger.warning(
                "File with ID %s not found or access denied for user %s",
                file_id,
                current_user.username,
            )
            return {"message": "File not found or access denied"}, 404

        shares = FileShare.query.filter_by(file_id=file.file_id, shared_by=current_user.id).all()
        share_list = []

        for share in shares:
            recipient = UserLogin.query.filter_by(id=share.shared_with).first()
            share_list.append(
                {
                    "share_id": share.id,
                    "shared_with": share.shared_with,
                    "shared_with_username": recipient.username if recipient else "Unknown",
                    "created_at": share.created_at.isoformat() if share.created_at else None,
                    "file_id": share.file_id,
                    "file_name": share.file_name,
                    "file_size": share.file_size,
                    "file_type": share.file_type,
                },
            )

        current_app.logger.info(
            "User %s retrieved %d shares for file %s",
            current_user.username,
            len(share_list),
            file.file_name,
        )
        return {"shares": share_list, "count": len(share_list)}, 200

    @shares_ns.doc(security="apikey")
    @shares_ns.expect(models["revoke_request_model"])
    @shares_ns.response(200, "Access revoked")
    @shares_ns.response(404, "File or share not found")
    @token_required
    def delete(self, current_user: UserLogin, file_id: str) -> tuple:
        """Revoke a user's access to a shared file"""
        data = request.get_json()
        shared_with_username = data.get("shared_with_username")

        if not shared_with_username:
            current_app.logger.warning("Missing recipient username for revoking access")
            return {"message": "Missing recipient username"}, 400

        file = File.query.filter_by(file_id=file_id, created_by=current_user.id).first()
        if not file:
            current_app.logger.warning(
                "File with ID %s not found or access denied for user %s",
                file_id,
                current_user.username,
            )
            return {"message": "File not found or access denied"}, 404

        recipient = UserLogin.query.filter_by(username=shared_with_username).first()
        if not recipient:
            current_app.logger.warning(
                "Recipient user %s not found for revoking access to file %s",
                shared_with_username,
                file.file_name,
            )
            return {"message": "Recipient user not found"}, 404

        share = FileShare.query.filter_by(
            file_id=file_id,
            shared_by=current_user.id,
            shared_with=recipient.id,
        ).first()
        if not share:
            current_app.logger.warning(
                "Share not found for file %s shared by user %s with recipient %s",
                file.file_name,
                current_user.username,
                recipient.username,
            )
            return {"message": "Share not found"}, 404

        try:
            db.session.delete(share)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("Error revoking share")
            return {"message": f"Error revoking share: {e!s}"}, 500
        else:
            current_app.logger.info(
                "User %s revoked access to file %s for user %s",
                current_user.username,
                file.file_name,
                recipient.username,
            )
            return {"message": "Access revoked"}, 200


@shares_ns.route("/shared-with-me")
class FilesSharedWithMe(Resource):
    @shares_ns.doc(security="apikey")
    @shares_ns.response(200, "Files shared with the user retrieved successfully", models["files_list_model"])
    @token_required
    def get(self, current_user: UserLogin) -> tuple:
        """Get all files shared with the current user"""
        try:
            shares = FileShare.query.filter_by(shared_with=current_user.id).all()
            files_data = []

            for share in shares:
                shared_by_user = UserLogin.query.filter_by(id=share.shared_by).first()
                files_data.append(
                    {
                        "share_id": share.id,
                        "file_id": share.file_id,
                        "file_name": share.file_name,
                        "file_type": share.file_type,
                        "file_size": share.file_size,
                        "shared_by": share.shared_by,
                        "shared_by_username": shared_by_user.username if shared_by_user else "Unknown",
                        "created_at": share.created_at.isoformat() if share.created_at else None,
                    },
                )

            current_app.logger.info("Retrieved %d shared files for user %s", len(files_data), current_user.username)
            return {"files": files_data, "count": len(files_data)}, 200
        except Exception:
            current_app.logger.exception("Database error retrieving shared files")
            return {"files": [], "count": 0}, 500


@shares_ns.route("/download/<share_id>")
@shares_ns.param("share_id", "The share identifier")
class SharedFileDownload(Resource):
    @shares_ns.doc(security="apikey")
    @shares_ns.response(200, "Encrypted file and cryptographic data retrieved successfully")
    @shares_ns.response(403, "Access denied")
    @shares_ns.response(404, "Shared file not found")
    @token_required
    def get(self, current_user: UserLogin, share_id: str) -> tuple[dict, int]:
        """Return **encrypted file** and all cryptographic artifacts for client-side decryption"""
        try:
            share = FileShare.query.filter_by(id=share_id, shared_with=current_user.id).first()
            if not share:
                current_app.logger.warning(
                    "Shared file with ID %s not found or access denied for user %s",
                    share_id,
                    current_user.username,
                )
                return {"message": "Shared file not found or access denied"}, 404

            sender = UserLogin.query.filter_by(id=share.shared_by).first()
            if not sender:
                current_app.logger.warning(
                    "Sender user %s not found for share ID %s",
                    share.shared_by,
                    share_id,
                )
                return {"message": "Sender user not found"}, 404

            response_data = {
                "file_id": share.file_id,
                "file_name": share.file_name,
                "file_type": share.file_type or "",
                "file_size": share.file_size or 0,
                "shared_by": share.shared_by,
                "shared_by_username": sender.username,
                "encrypted_file": base64.b64encode(share.encrypted_file).decode(),
                "nonce": base64.b64encode(share.nonce).decode(),
                "ephemeral_public_key": base64.b64encode(share.ephemeral_public_key).decode(),
                "sender_signature": base64.b64encode(share.sender_signature).decode(),
                "sender_x25519_public_key": sender.public_key,
                "sender_ed25519_public_key": sender.signing_public_key,
                "created_at": share.created_at.isoformat() if share.created_at else None,
            }

            current_app.logger.info(
                "Cryptographic data for file %s served to user %s",
                share.file_name,
                current_user.username,
            )

        except Exception as e:
            current_app.logger.exception("Error retrieving shared file data")
            return {"message": f"Error retrieving file: {e!s}"}, 500
        else:
            return response_data, 200
