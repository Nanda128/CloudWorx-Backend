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
    shared_with = db.Column(
        db.String(36),
        db.ForeignKey("user_login.id", ondelete="CASCADE"),
        nullable=False,
    )
    encrypted_dek = db.Column(db.LargeBinary(length=255), nullable=False)
    assoc_data_dek = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    def __init__(  # noqa: PLR0913
        self,
        share_id: str,
        file_id: str,
        shared_with: str,
        encrypted_dek: bytes,
        iv_dek: str,
        assoc_data_dek: str = "File of file ID {file_id} shared with {shared_with}",
    ) -> None:
        self.share_id = share_id
        self.file_id = file_id
        self.shared_with = shared_with
        self.encrypted_dek = encrypted_dek
        self.iv_dek = iv_dek
        self.assoc_data_dek = (
            assoc_data_dek.format(file_id=file_id, shared_with=shared_with)
            if assoc_data_dek == "File of file ID {file_id} shared with {shared_with}"
            else assoc_data_dek
        )
        self.created_at = datetime.now(timezone.utc)

    def __repr__(self) -> str:
        return f"<FileShare file_id={self.file_id} shared_with={self.shared_with}>"
