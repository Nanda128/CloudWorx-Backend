import base64  # noqa: INP001
import io
import uuid
from functools import wraps
from typing import Any, Callable

import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Request, current_app, jsonify, request, send_file
from flask_restx import Namespace, Resource, fields
from markupsafe import escape
from pqcrypto.kem.mceliece8192128 import encrypt
from werkzeug.utils import secure_filename

from app import db
from app.models.file import File, FileDEK, FileShare
from app.models.user import UserLogin

files_ns = Namespace("files", description="File upload, download, and management")

file_dek_model = files_ns.model(
    "FileDEK",
    {
        "key_id": fields.String,
        "iv_dek": fields.String(description="Base64-encoded IV for DEK"),
        "encrypted_dek": fields.String(description="Base64-encoded encrypted DEK"),
        "assoc_data_dek": fields.String(description="Associated data for DEK"),
    },
)

file_model = files_ns.model(
    "File",
    {
        "file_id": fields.String(description="Unique identifier for the file"),
        "file_name": fields.String(description="Name of the file"),
        "iv_file": fields.String(description="Base64-encoded IV for file"),
        "assoc_data_file": fields.String(description="Associated data for file"),
        "created_at": fields.String(description="Creation timestamp of the file", example="2023-10-01T12:00:00Z"),
        "dek_data": fields.Nested(file_dek_model, allow_null=True),
    },
)

files_list_model = files_ns.model(
    "FilesList",
    {
        "files": fields.List(fields.Nested(file_model)),
        "count": fields.Integer(description="Total number of files owned by the user"),
    },
)

upload_response_model = files_ns.model(
    "UploadResponse",
    {
        "message": fields.String(description="Success message after file upload"),
        "file_id": fields.String(description="The ID of the uploaded file"),
        "file_name": fields.String(description="The name of the uploaded file"),
    },
)

delete_response_model = files_ns.model(
    "DeleteResponse",
    {
        "message": fields.String(description="Success message after file deletion"),
    },
)

share_request_model = files_ns.model(
    "ShareRequest",
    {
        "shared_with_username": fields.String(required=True, description="Username of the recipient"),
        "encrypted_dek": fields.String(required=True, description="Base64-encoded DEK encrypted for recipient"),
        "iv_dek": fields.String(required=True, description="Base64-encoded IV for DEK"),
        "assoc_data_dek": fields.String(required=True, description="Associated data for DEK"),
    },
)

share_response_model = files_ns.model(
    "ShareResponse",
    {
        "message": fields.String(description="Success message after sharing the file"),
        "share_id": fields.String(description="The ID of the share"),
        "shared_with": fields.String(description="The ID of the user the file was shared with"),
    },
)

share_list_model = files_ns.model(
    "ShareList",
    {
        "shares": fields.List(
            fields.Nested(
                files_ns.model(
                    "ShareInfo",
                    {
                        "share_id": fields.String(description="Unique identifier for the share"),
                        "shared_with": fields.String(description="ID of the user the file is shared with"),
                        "shared_with_username": fields.String(description="Username of the recipient"),
                        "created_at": fields.String(description="Creation timestamp of the share", example="2023-10-01T12:00:00Z"),
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

revoke_request_model = files_ns.model(
    "RevokeRequest",
    {
        "shared_with_username": fields.String(required=True, description="Username of the recipient to revoke"),
    },
)

file_id_response_model = files_ns.model(
    "FileIdResponse",
    {
        "file_id": fields.String(required=True, description="The ID of the file"),
    },
)


def token_required(f: Callable) -> Callable:
    """Check for a valid JWT token in the request headers."""

    @wraps(f)
    def decorated(*args: object, **kwargs: object) -> object:
        token = None
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if " " in auth_header:
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        try:
            data = jwt.decode(token, current_app.config["JWT_SECRET_KEY"], algorithms=["HS256"])
            current_user = UserLogin.query.filter_by(id=data["user_id"]).first()
            if not current_user:
                return jsonify({"message": "User not found!"}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token!"}), 401
        return f(current_user, *args, **kwargs)

    return decorated


def allowed_file(filename: str) -> bool:
    allowed_extensions = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "doc", "docx", "xls", "xlsx"}
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


@files_ns.route("")
class FilesList(Resource):
    @files_ns.doc(security="apikey")
    @files_ns.marshal_with(files_list_model)
    @token_required
    def get(self, current_user: UserLogin) -> tuple:
        """Get info on all files owned by the current user"""
        try:
            files = File.query.filter_by(created_by=current_user.id).all()
            files_data = []
            for file in files:
                dek = FileDEK.query.filter_by(file_id=file.file_id).first()
                if dek:
                    dek_data = {
                        "key_id": dek.key_id,
                        "iv_dek": dek.iv_dek,
                        "encrypted_dek": dek.encrypted_dek,
                        "assoc_data_dek": dek.assoc_data_dek,
                    }
                else:
                    dek_data = None
                files_data.append(
                    {
                        "file_id": file.file_id,
                        "file_name": file.file_name,
                        "iv_file": file.iv_file,
                        "assoc_data_file": file.assoc_data_file,
                        "created_at": file.created_at.isoformat(),
                        "dek_data": dek_data,
                    },
                )
            return {
                "files": files_data,
                "count": len(files_data),
            }, 200
        except db.exc.SQLAlchemyError:
            current_app.logger.exception("Database error retrieving files")
            return {"files": [], "count": 0}, 500

    @files_ns.doc(security="apikey")
    @files_ns.response(201, "File uploaded successfully", upload_response_model)
    @files_ns.response(400, "Validation error")
    @token_required
    def post(self, current_user: UserLogin) -> tuple:
        """Upload a new encrypted file"""
        try:
            (
                file,
                file_name,
                iv_file,
                file_type,
                file_size,
                iv_dek,
                encrypted_dek,
                assoc_data_dek,
                error_response,
            ) = _validate_upload_request(request)
            if error_response:
                return error_response
            file_id = str(uuid.uuid4())
            key_id = str(uuid.uuid4())
            assoc_data_file = f"File with ID {file_id} belonging to user {current_user.id}"

            new_file = File(
                File.FileParams(
                    file_id=file_id,
                    file_name=file_name,
                    iv_file=iv_file,
                    encrypted_file=file.read(),
                    assoc_data_file=assoc_data_file,
                    file_type=file_type,
                    file_size=file_size,
                ),
                created_by=current_user.id,
            )
            new_dek = FileDEK(
                key_id=key_id,
                file_id=file_id,
                dek_params=FileDEK.DEKParams(
                    iv_dek=iv_dek,
                    encrypted_dek=encrypted_dek,
                    assoc_data_dek=assoc_data_dek,
                ),
            )
            db.session.add(new_file)
            db.session.add(new_dek)
            db.session.commit()
            return {  # noqa: TRY300
                "message": "File uploaded successfully",
                "file_id": file_id,
                "file_name": file_name,
            }, 201
        except (db.exc.SQLAlchemyError, OSError) as e:
            db.session.rollback()
            current_app.logger.exception("Error uploading file", exc_info=e)
            return jsonify({"message": f"Error uploading file: {str(e)!s}"}), 500


@files_ns.route("/<file_id>/share")
@files_ns.param("file_id", "The file identifier")
class FileShareResource(Resource):
    @files_ns.doc(security="apikey")
    @files_ns.expect(share_request_model)
    @files_ns.response(201, "File shared successfully", share_response_model)
    @files_ns.response(404, "File or recipient not found")
    @files_ns.response(403, "Access denied")
    @token_required
    def post(self, current_user: UserLogin, file_id: str) -> tuple:
        """Share a file with another user (by username) and re-encrypt DEK with recipient's public key"""

        data = request.get_json()
        file = File.query.filter_by(file_id=file_id, created_by=current_user.id).first()
        if not file:
            return jsonify({"message": "File not found or access denied"}), 404

        recipient = UserLogin.query.filter_by(username=data.get("shared_with_username")).first()
        if not recipient:
            return jsonify({"message": "Recipient user not found"}), 404
        if recipient.id == current_user.id:
            return jsonify({"message": "Cannot share file with yourself"}), 400

        existing = FileShare.query.filter_by(file_id=file_id, shared_with=recipient.id).first()
        if existing:
            return jsonify({"message": "File already shared with this user"}), 400

        pdk = data["password-derived-key"]
        if not pdk:
            return jsonify({"message": "Missing password-derived key"}), 400

        encrypted_kek = base64.b64decode(current_user.encrypted_kek)
        kek_iv = base64.b64decode(current_user.kek_iv)
        aesgcm = AESGCM(pdk)
        kek = aesgcm.decrypt(kek_iv, encrypted_kek, None)

        file_dek = FileDEK.query.filter_by(file_id=file_id).first()
        if not file_dek:
            return jsonify({"message": "File DEK not found"}), 404
        dek_iv = base64.b64decode(file_dek.iv_dek)
        share_encryped_dek = base64.b64decode(file_dek.encrypted_dek)
        aesgcm_kek = AESGCM(kek)
        dek = aesgcm_kek.decrypt(dek_iv, share_encryped_dek, file_dek.assoc_data_dek.encode())

        ct, _ = encrypt(base64.b64decode(recipient.public_key), dek) # BEWARE: This encrypt() is for CRYSTALS-Kyber KEM, not AESGCM.
        share_encryped_dek = base64.b64encode(ct)

        share = FileShare(
            share_id=str(uuid.uuid4()),
            file_id=file_id,
            shared_with=recipient.id,
            encrypted_dek=share_encryped_dek,
            assoc_data_dek=file_dek.assoc_data_dek,
        )
        db.session.add(share)
        db.session.commit()
        return {
            "message": "File shared successfully",
            "share_id": share.share_id,
            "shared_with": recipient.id,
        }, 201

    @files_ns.doc(security="apikey")
    @files_ns.marshal_with(share_list_model)
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

    @files_ns.doc(security="apikey")
    @files_ns.expect(revoke_request_model)
    @files_ns.response(200, "Access revoked")
    @files_ns.response(404, "File or share not found")
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


@files_ns.route("/shared-with-me/<user_id>")
@files_ns.param("user_id", "The user identifier")
class FilesSharedWithMe(Resource):
    @files_ns.doc(security="apikey")
    @files_ns.marshal_with(files_list_model)
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


@files_ns.route("/<file-name>")
@files_ns.param("file-name", "The file ID or file name")
class FileResource(Resource):
    @files_ns.doc(security="apikey", params={"by_name": 'Set to "true" to search by file name instead of ID'})
    @files_ns.response(200, "File downloaded")
    @files_ns.response(403, "Access denied")
    @files_ns.response(404, "File not found")
    @token_required
    def get(self, current_user: UserLogin, file_name: str) -> tuple:
        """Download an encrypted file by name only"""
        try:
            file = File.query.filter_by(file_name=file_name).first()
            if not file:
                return jsonify({"message": "File not found"}), 404
            is_owner = file.created_by == current_user.id
            is_shared = False
            if not is_owner:
                share = FileShare.query.filter_by(file_id=file.file_id, shared_with=current_user.id).first()
                if not share:
                    return jsonify({"message": "Access denied"}), 403
                is_shared = True
            if not is_shared:
                dek = FileDEK.query.filter_by(file_id=file.file_id).first()
                if not dek:
                    return jsonify({"message": "File encryption key not found"}), 404
                response = send_file(
                    io.BytesIO(file.encrypted_file),
                    mimetype="application/octet-stream",
                    as_attachment=True,
                    download_name=file.file_name,
                )
                response.headers["X-File-ID"] = file.file_id
                response.headers["X-File-Name"] = file.file_name
                response.headers["X-File-Type"] = file.file_type
                response.headers["X-File-IV"] = file.iv_file
                response.headers["X-File-Assoc-Data"] = file.assoc_data_file
                response.headers["X-File-DEK"] = dek.key_id if dek else ""
                response.headers["X-File-DEK-IV"] = dek.iv_dek if dek else ""
                return response, 200
            response = send_file(
                io.BytesIO(file.encrypted_file),
                mimetype="application/octet-stream",
                as_attachment=True,
                download_name=file.file_name,
            )
            response.headers["X-File-ID"] = file.file_id
            response.headers["X-File-Name"] = file.file_name
            response.headers["X-File-Type"] = file.file_type
            response.headers["X-File-IV"] = file.iv_file
            response.headers["X-File-Assoc-Data"] = file.assoc_data_file
            response.headers["X-File-DEK"] = share.encryped_dek if dek else ""
            return response, 200  # noqa: TRY300
        except (db.exc.SQLAlchemyError, OSError) as e:
            return jsonify({"message": f"Error downloading file: {str(e)!s}"}), 500

    @files_ns.doc(security="apikey")
    @files_ns.response(200, "File deleted successfully", delete_response_model)
    @files_ns.response(404, "File not found or access denied")
    @token_required
    def delete(self, current_user: UserLogin, file_name: str) -> tuple:
        """Delete a file and its associated DEK and any shares"""
        try:
            file = File.query.filter_by(file_id=file_name, created_by=current_user.id).first()
            if not file:
                return jsonify({"message": "File not found or access denied"}), 404
            share = FileShare.query.filter_by(file_id=file_name)
            if not share:
                db.session.delete(share)

            db.session.delete(file)
            db.session.commit()
            return {"message": "File deleted successfully"}, 200  # noqa: TRY300
        except (db.exc.SQLAlchemyError, OSError) as e:
            db.session.rollback()
            return jsonify({"message": f"Error deleting file: {str(e)!s}"}), 500

@files_ns.route("/resolve-id/<file_name>")
@files_ns.param("file_name", "The name of the file to resolve")
class FileIdResolver(Resource):
    @files_ns.doc(security="apikey")
    @files_ns.response(200, "File ID resolved", file_id_response_model)
    @files_ns.response(404, "File not found")
    @token_required
    def get(self, current_user: UserLogin, file_name: str) -> tuple:
        """Resolve a file name to its file ID for the current user"""
        file = File.query.filter_by(file_name=file_name, created_by=current_user.id).first()
        if not file:
            return jsonify({"message": "File not found"}), 404
        return {"file_id": file.file_id}, 200

def _validate_upload_request(request: Request) -> tuple[Any, Any, Any, Any, Any, Any, Any, Any, Any]:
    """Validate the upload request and extract file and DEK information"""
    file = None
    error_response = None
    file_name = None
    iv_file = None
    file_type = None
    file_size = None
    iv_dek = None
    encrypted_dek = None
    assoc_data_dek = None

    if "encrypted_file" not in request.files:
        error_response = (jsonify({"message": "No file part in the request"}), 400)
    else:
        file = request.files["encrypted_file"]

        if file.filename == "":
            error_response = (jsonify({"message": "No file selected"}), 400)
        else:
            file_name = request.form.get("file_name")
            if not file_name:
                file_name = secure_filename(file.filename or "")
            file_name = escape(file_name)

            iv_file = request.form.get("iv_file")
            file_type = request.form.get("file_type")
            file_size = request.form.get("file_size")
            try:
                file_size = int(file_size) if file_size is not None else None
            except ValueError:
                file_size = None

            iv_dek = request.form.get("iv_dek")
            encrypted_dek = request.form.get("encrypted_dek")
            assoc_data_dek = request.form.get("assoc_data_dek")

            if not iv_file:
                error_response = (jsonify({"message": "Missing IV for file encryption"}), 400)
            elif not all([iv_dek, encrypted_dek, assoc_data_dek]):
                error_response = (jsonify({"message": "Missing DEK encryption data"}), 400)

    if error_response:
        return (
            file,
            file_name,
            iv_file,
            file_type,
            file_size,
            iv_dek,
            encrypted_dek,
            assoc_data_dek,
            error_response,
        )

    if not file or not allowed_file(file.filename or "") or not file_name or not iv_file:
        return (
            file,
            file_name,
            iv_file,
            file_type,
            file_size,
            iv_dek,
            encrypted_dek,
            assoc_data_dek,
            (jsonify({"message": "Missing required fields for file information"}), 400),
        )

    if not iv_dek or not encrypted_dek or not assoc_data_dek:
        return (
            file,
            file_name,
            iv_file,
            file_type,
            file_size,
            iv_dek,
            encrypted_dek,
            assoc_data_dek,
            (jsonify({"message": "Missing required fields for file DEK information"}), 400),
        )

    return (
        file,
        file_name,
        iv_file,
        file_type,
        file_size,
        iv_dek,
        encrypted_dek,
        assoc_data_dek,
        None,
    )
