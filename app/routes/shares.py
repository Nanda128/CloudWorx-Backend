from __future__ import annotations

import io
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from flask import Response, current_app, request, send_file
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


@shares_ns.route("/public-key/<username>")
@shares_ns.param("username", "The username to get public key for")
class PublicKeyResource(Resource):
    @shares_ns.doc(security="apikey")
    @shares_ns.response(200, "Public key retrieved successfully")
    @shares_ns.response(404, "User not found")
    @token_required
    def get(self, _current_user: UserLogin, username: str) -> tuple:
        """Get another user's public key for sharing"""
        user = UserLogin.query.filter_by(username=username).first()
        if not user:
            current_app.logger.warning("User %s not found for public key request", username)
            return {"message": "User not found"}, 404

        try:
            key = serialization.load_pem_public_key(user.public_key.encode("utf-8"))
            if not isinstance(key, x25519.X25519PublicKey):
                current_app.logger.warning("User %s does not have a valid X25519 public key", username)
                return {"message": "User does not have a valid X25519 public key"}, 400
        except (ValueError, TypeError):
            current_app.logger.warning("Invalid public key format for user %s", username)
            return {"message": "User has invalid public key format"}, 400

        is_trusted, tofu_message, _ = verify_tofu_key(user.id, user.public_key)
        if not is_trusted:
            current_app.logger.warning("TOFU verification failed for public key request: %s", tofu_message)
            return {"message": f"Key verification failed: {tofu_message}"}, 400

        return {
            "username": user.username,
            "user_id": user.id,
            "public_key": user.public_key,
            "tofu_message": tofu_message,
        }, 200


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
        """Share a file with another user by copying file data"""
        data = request.get_json()
        shared_with_username = data.get("shared_with_username")

        if not shared_with_username:
            current_app.logger.warning("Missing recipient username for sharing")
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
                "Recipient user %s not found for sharing file %s",
                shared_with_username,
                file.file_name,
            )
            return {"message": "Recipient user not found"}, 404

        if recipient.id == current_user.id:
            current_app.logger.warning(
                "User %s attempted to share file %s with themselves",
                current_user.username,
                file.file_name,
            )
            return {"message": "Cannot share file with yourself"}, 400

        existing_share = FileShare.query.filter_by(file_id=file_id, shared_with=recipient.id).first()
        if existing_share:
            current_app.logger.warning(
                "File %s already shared with user %s",
                file.file_name,
                recipient.username,
            )
            return {"message": "File already shared with this user"}, 400

        is_trusted, tofu_message, _ = verify_tofu_key(recipient.id, recipient.public_key)
        if not is_trusted:
            current_app.logger.warning("TOFU verification failed for sharing: %s", tofu_message)
            return {"message": f"Key verification failed: {tofu_message}"}, 400

        try:
            share = FileShare(
                id=str(uuid.uuid4()),
                file_id=file.file_id,
                shared_by=current_user.id,
                shared_with=recipient.id,
                file_name=file.file_name,
                file_type=file.file_type,
                file_size=file.file_size,
                encrypted_file=file.encrypted_file,
            )

            db.session.add(share)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("Error sharing file")
            return {"message": f"Error sharing file: {e!s}"}, 500
        else:
            return {
                "message": "File shared successfully",
                "share_id": share.id,
                "shared_with": recipient.id,
                "tofu_message": tofu_message,
            }, 201

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
            return {"shares": [], "count": 0}, 404

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
    @shares_ns.response(200, "Access revoked", models["revoke_response_model"])
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
            current_app.logger.info("User %s requested files shared with them", current_user.username)
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
    @shares_ns.response(200, "File downloaded successfully")
    @shares_ns.response(403, "Access denied")
    @shares_ns.response(404, "Shared file not found")
    @token_required
    def get(self, current_user: UserLogin, share_id: str) -> Response | tuple[dict, int]:
        """Download a file that has been shared with the current user"""
        try:
            current_app.logger.info(
                "User %s requested download of shared file with ID %s",
                current_user.username,
                share_id,
            )
            share = FileShare.query.filter_by(id=share_id, shared_with=current_user.id).first()
            if not share:
                current_app.logger.warning(
                    "Shared file with ID %s not found or access denied for user %s",
                    share_id,
                    current_user.username,
                )
                return {"message": "Shared file not found or access denied"}, 404

            response = send_file(
                io.BytesIO(share.encrypted_file),
                mimetype="application/octet-stream",
                as_attachment=True,
                download_name=share.file_name,
            )

            response.headers["X-File-ID"] = share.file_id
            response.headers["X-File-Name"] = share.file_name
            response.headers["X-File-Type"] = share.file_type or ""
            response.headers["X-File-Size"] = str(share.file_size or 0)
            response.headers["X-Shared-By"] = share.shared_by

        except Exception as e:
            current_app.logger.exception("Error downloading shared file")
            return {"message": f"Error downloading file: {e!s}"}, 500
        else:
            current_app.logger.info("File %s downloaded by user %s", share.file_name, current_user.username)
            return response
