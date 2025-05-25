from dataclasses import dataclass  # noqa: INP001
from datetime import datetime, timezone

from app import db


class File(db.Model):
    __tablename__ = "files"

    file_id = db.Column(
        db.String(36),
        primary_key=True,
        nullable=False,
    )
    file_name = db.Column(db.String(255), unique=True, nullable=False)
    iv_file = db.Column(db.String(255), nullable=False)
    encrypted_file = db.Column(db.LargeBinary(length=(2**32) - 1), nullable=False)  # MySQL LONGBLOB
    assoc_data_file = db.Column(db.String(255), nullable=False)
    created_by = db.Column(
        db.String(36),
        db.ForeignKey("user_login.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    file_type = db.Column(db.String(32), nullable=True)
    file_size = db.Column(db.Integer, nullable=True)

    dek = db.relationship(
        "FileDEK",
        backref="file",
        uselist=False,
        cascade="all, delete-orphan",
    )
    shares = db.relationship(
        "FileShare",
        backref="file",
        lazy=True,
        cascade="all, delete-orphan",
    )

    @dataclass
    class FileParams:
        file_id: str
        file_name: str
        iv_file: str
        encrypted_file: bytes
        file_type: str
        file_size: int

    def __init__(
        self,
        file_params: "File.FileParams",
        created_by: str,
    ) -> None:
        self.file_id = file_params.file_id
        self.file_name = file_params.file_name
        self.iv_file = file_params.iv_file
        self.encrypted_file = file_params.encrypted_file
        self.assoc_data_file = "File {file_name} with ID {file_id} created by {created_by}"
        self.created_by = created_by
        self.created_at = datetime.now(timezone.utc)
        self.file_type = file_params.file_type
        self.file_size = file_params.file_size

    def __repr__(self) -> str:
        return f"<File {self.file_name}>"


class FileDEK(db.Model):
    __tablename__ = "file_dek"

    key_id = db.Column(
        db.String(36),
        primary_key=True,
        nullable=False,
    )
    file_id = db.Column(
        db.String(36),
        db.ForeignKey("files.file_id", ondelete="CASCADE"),
        nullable=False,
    )
    iv_dek = db.Column(db.String(255), nullable=False)
    encrypted_dek = db.Column(db.String(255), nullable=False)
    assoc_data_dek = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    def __init__(
        self,
        key_id: str,
        file_id: str,
        iv_dek: str,
        encrypted_dek: str,
    ) -> None:
        self.key_id = key_id
        self.file_id = file_id
        self.iv_dek = iv_dek
        self.encrypted_dek = encrypted_dek
        self.assoc_data_dek = "DEK for file ID {file_id} with key ID {key_id}"
        self.created_at = datetime.now(timezone.utc)

    def __repr__(self) -> str:
        return f"<FileDEK {self.key_id}>"


class FileShare(db.Model):
    __tablename__ = "file_share"

    share_id = db.Column(db.String(36), primary_key=True, nullable=False)
    file_id = db.Column(
        db.String(36),
        db.ForeignKey("files.file_id", ondelete="CASCADE"),
        nullable=False,
    )
    shared_with = db.Column(
        db.String(36),
        db.ForeignKey("user_login.id", ondelete="CASCADE"),
        nullable=False,
    )
    encrypted_dek = db.Column(db.LargeBinary(length=255), nullable=False)
    assoc_data_dek = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    def __init__(
        self,
        share_id: str,
        file_id: str,
        shared_with: str,
        encrypted_dek: bytes,
    ) -> None:
        self.share_id = share_id
        self.file_id = file_id
        self.shared_with = shared_with
        self.encrypted_dek = encrypted_dek
        self.assoc_data_dek = "File of file ID {file_id} shared with {shared_with}"
        self.created_at = datetime.now(timezone.utc)

    def __repr__(self) -> str:
        return f"<FileShare file_id={self.file_id} shared_with={self.shared_with}>"
