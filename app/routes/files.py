import io  # noqa: INP001
import uuid
from typing import Any

from flask import Request, current_app, request, send_file
from flask_restx import Namespace, Resource
from markupsafe import escape
from werkzeug.utils import secure_filename

from app import db
from app.docs.files_docs import register_files_models
from app.models.file import File, FileDEK
from app.models.share import FileShare
from app.models.user import UserLogin
from app.utils.token import token_required

files_ns = Namespace("files", description="File upload, download, and management")

models = register_files_models(files_ns)


def allowed_file(filename: str) -> bool:
    allowed_extensions = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "doc", "docx", "xls", "xlsx"}
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


@files_ns.route("")
class FilesList(Resource):
    @files_ns.doc(security="apikey")
    @files_ns.marshal_with(models["files_list_model"])
    @files_ns.response(200, "Files retrieved successfully")
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
    @files_ns.expect(models["file_upload_model"])
    @files_ns.marshal_with(models["upload_response_model"])
    @files_ns.response(201, "File uploaded successfully")
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
                error_response,
            ) = _validate_upload_request(request)
            if error_response:
                return error_response
            file_id = str(uuid.uuid4())
            key_id = str(uuid.uuid4())

            new_file = File(
                File.FileParams(
                    file_id=file_id,
                    file_name=file_name,
                    iv_file=iv_file,
                    encrypted_file=file.read(),
                    file_type=file_type,
                    file_size=file_size,
                ),
                created_by=current_user.id,
            )
            new_dek = FileDEK(
                key_id=key_id,
                file_id=file_id,
                iv_dek=iv_dek,
                encrypted_dek=encrypted_dek,
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
            return {"message": f"Error uploading file: {str(e)!s}"}, 500


@files_ns.route("/<file_name>")
@files_ns.param("file-name", "The file ID or file name")
class FileResource(Resource):
    @files_ns.doc(security="apikey")
    @files_ns.response(200, "File downloaded")
    @files_ns.response(403, "Access denied")
    @files_ns.response(404, "File not found")
    @token_required
    def get(self, current_user: UserLogin, file_name: str) -> tuple:
        """Download an encrypted file by name"""
        try:
            file = File.query.filter_by(file_name=file_name).first()
            if not file:
                return {"message": "File not found"}, 404
            is_owner = file.created_by == current_user.id
            is_shared = False
            dek = FileDEK.query.filter_by(file_id=file.file_id).first()
            share = None
            if not dek:
                return {"message": "File encryption key not found"}, 404
            if not is_owner:
                share = FileShare.query.filter_by(file_id=file.file_id, shared_with=current_user.id).first()
                if not share:
                    return {"message": "Access denied"}, 403
                is_shared = True
            if not is_shared:
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
            response.headers["X-File-DEK"] = share.encryped_dek if share and dek else ""
            return response, 200  # noqa: TRY300
        except (db.exc.SQLAlchemyError, OSError) as e:
            return {"message": f"Error downloading file: {str(e)!s}"}, 500

    @files_ns.doc(security="apikey")
    @files_ns.response(200, "File deleted successfully", models["delete_response_model"])
    @files_ns.response(404, "File not found or access denied")
    @token_required
    def delete(self, current_user: UserLogin, file_name: str) -> tuple:
        """Delete a file and its associated DEK and any shares"""
        try:
            file = File.query.filter_by(file_id=file_name, created_by=current_user.id).first()
            if not file:
                return {"message": "File not found or access denied"}, 404
            share = FileShare.query.filter_by(file_id=file_name)
            if not share:
                db.session.delete(share)

            db.session.delete(file)
            db.session.commit()
            return {"message": "File deleted successfully"}, 200  # noqa: TRY300
        except (db.exc.SQLAlchemyError, OSError) as e:
            db.session.rollback()
            return {"message": f"Error deleting file: {str(e)!s}"}, 500


@files_ns.route("/resolve-id/<file_name>")
@files_ns.param("file_name", "The name of the file to resolve")
class FileIdResolver(Resource):
    @files_ns.doc(security="apikey")
    @files_ns.response(200, "File ID resolved", models["file_id_response_model"])
    @files_ns.response(404, "File not found")
    @token_required
    def get(self, current_user: UserLogin, file_name: str) -> tuple:
        """Resolve a file name to its file ID for the current user"""
        file = File.query.filter_by(file_name=file_name, created_by=current_user.id).first()
        if not file:
            return {"message": "File not found"}, 404
        return {"file_id": file.file_id}, 200


def _validate_upload_request(request: Request) -> tuple[Any, Any, Any, Any, Any, Any, Any, Any]:
    """Validate the upload request and extract file and DEK information from headers"""
    file = None
    error_response = None
    file_name = None
    iv_file = None
    file_type = None
    file_size = None
    iv_dek = None
    encrypted_dek = None

    if "encrypted_file" not in request.files:
        error_response = ({"message": "No file part in the request"}, 400)
    else:
        file = request.files["encrypted_file"]

        if file.filename == "":
            error_response = {"message": "No file selected"}, 400
        else:
            file_name = request.headers.get("X-File-Name")
            if not file_name:
                file_name = secure_filename(file.filename or "")
            file_name = escape(file_name)

            iv_file = request.headers.get("X-IV-File")
            file_type = request.headers.get("X-File-Type")
            file_size = request.headers.get("X-File-Size")
            try:
                file_size = int(file_size) if file_size is not None else None
            except ValueError:
                file_size = None

            iv_dek = request.headers.get("X-IV-DEK")
            encrypted_dek = request.headers.get("X-Encrypted-DEK")

            if not iv_file:
                error_response = ({"message": "Missing IV for file encryption"}, 400)
            elif not all([iv_dek, encrypted_dek]):
                error_response = ({"message": "Missing DEK encryption data"}, 400)

    if error_response:
        return (
            file,
            file_name,
            iv_file,
            file_type,
            file_size,
            iv_dek,
            encrypted_dek,
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
            ({"message": "Missing required fields for file information"}, 400),
        )

    if not iv_dek or not encrypted_dek:
        return (
            file,
            file_name,
            iv_file,
            file_type,
            file_size,
            iv_dek,
            encrypted_dek,
            ({"message": "Missing required fields for file DEK information"}, 400),
        )

    return (
        file,
        file_name,
        iv_file,
        file_type,
        file_size,
        iv_dek,
        encrypted_dek,
        None,
    )
