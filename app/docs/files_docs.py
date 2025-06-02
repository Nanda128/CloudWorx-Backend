from flask_restx import Namespace, fields  # noqa: INP001


def register_files_models(files_ns: Namespace) -> dict:
    """Register models for file-related API endpoints"""

    files_ns.authorizations = {
        "apikey": {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "JWT token in format: Bearer <token>",
        },
    }

    dek_data_model = files_ns.model(
        "DEKData",
        {
            "key_id": fields.String(description="DEK key ID"),
            "iv_dek": fields.String(description="Initialization vector for DEK"),
            "encrypted_dek": fields.String(description="Encrypted data encryption key"),
            "assoc_data_dek": fields.String(description="Associated data for DEK"),
        },
    )

    file_info_model = files_ns.model(
        "FileInfo",
        {
            "file_id": fields.String(description="File ID"),
            "file_name": fields.String(description="File name"),
            "iv_file": fields.String(description="Initialization vector for file"),
            "assoc_data_file": fields.String(description="Associated data for file"),
            "created_at": fields.String(description="File creation timestamp"),
            "dek_data": fields.Nested(dek_data_model, description="DEK data for file", allow_null=True),
        },
    )

    file_upload_parser = files_ns.parser()
    file_upload_parser.add_argument(
        "encrypted_file",
        location="files",
        type="file",
        required=True,
        help="The encrypted file to upload",
    )
    file_upload_parser.add_argument(
        "X-File-Name",
        location="headers",
        required=False,
        help="Custom file name (uses filename from uploaded file if not provided)",
    )
    file_upload_parser.add_argument(
        "X-IV-File",
        location="headers",
        required=True,
        help="Initialization Vector used for file encryption",
    )
    file_upload_parser.add_argument(
        "X-File-Type",
        location="headers",
        required=False,
        help="Type/MIME type of the file",
    )
    file_upload_parser.add_argument(
        "X-File-Size",
        location="headers",
        required=False,
        type=int,
        help="Size of the file in bytes",
    )
    file_upload_parser.add_argument(
        "X-IV-DEK",
        location="headers",
        required=True,
        help="Initialization Vector used for DEK encryption",
    )
    file_upload_parser.add_argument(
        "X-Encrypted-DEK",
        location="headers",
        required=True,
        help="Encrypted Data Encryption Key (DEK)",
    )

    file_download_headers = {
        "X-File-ID": "Unique identifier for the file",
        "X-File-Name": "Name of the file",
        "X-File-Type": "MIME type of the file",
        "X-File-IV": "Initialization vector used for file encryption",
        "X-File-Assoc-Data": "Associated data for file encryption",
        "X-File-DEK": "Data Encryption Key ID",
        "X-File-DEK-IV": "DEK Initialization vector",
    }

    return {
        "files_list_model": files_ns.model(
            "FilesList",
            {
                "files": fields.List(fields.Nested(file_info_model)),
                "count": fields.Integer(description="Total number of files"),
            },
        ),
        "upload_response_model": files_ns.model(
            "UploadResponse",
            {
                "message": fields.String(description="Status message"),
                "file_id": fields.String(description="ID of the uploaded file"),
                "file_name": fields.String(description="Name of the uploaded file"),
            },
        ),
        "file_id_response_model": files_ns.model(
            "FileIdResponse",
            {
                "file_id": fields.String(description="File ID"),
            },
        ),
        "file_upload_model": file_upload_parser,
        "file_download_headers": file_download_headers,
    }
