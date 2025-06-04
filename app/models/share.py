from datetime import datetime, timezone

from app import db


class FileShare(db.Model):
    __tablename__ = "file_share"

    id = db.Column(db.String(36), primary_key=True, nullable=False)
    file_id = db.Column(
        db.String(36),
        db.ForeignKey("files.file_id", ondelete="CASCADE"),
        nullable=False,
    )
    shared_by = db.Column(
        db.String(36),
        db.ForeignKey("user_login.id", ondelete="CASCADE"),
        nullable=False,
    )
    shared_with = db.Column(
        db.String(36),
        db.ForeignKey("user_login.id", ondelete="CASCADE"),
        nullable=False,
    )
    file_name = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(32), nullable=True)
    file_size = db.Column(db.Integer, nullable=True)
    encrypted_file = db.Column(db.LargeBinary(length=(2**32) - 1), nullable=False)
    nonce = db.Column(db.LargeBinary(length=32), nullable=False)
    ephemeral_public_key = db.Column(db.LargeBinary(length=32), nullable=False)
    sender_signature = db.Column(db.LargeBinary(length=64), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    def __init__(  # noqa: PLR0913
        self,
        id: str,  # noqa: A002
        file_id: str,
        shared_by: str,
        shared_with: str,
        file_name: str,
        file_type: str,
        file_size: int,
        encrypted_file: bytes,
        nonce: bytes,
        ephemeral_public_key: bytes,
        sender_signature: bytes,
    ) -> None:
        self.id = id
        self.file_id = file_id
        self.shared_by = shared_by
        self.shared_with = shared_with
        self.file_name = file_name
        self.file_type = file_type
        self.file_size = file_size
        self.encrypted_file = encrypted_file
        self.nonce = nonce
        self.ephemeral_public_key = ephemeral_public_key
        self.sender_signature = sender_signature
        self.created_at = datetime.now(timezone.utc)

    def __repr__(self) -> str:
        return f"<FileShare file_id={self.file_id} shared_by={self.shared_by} shared_with={self.shared_with}>"
