import uuid  # noqa: INP001
from datetime import datetime, timezone

from app import db


class FileShare(db.Model):
    __tablename__ = "file_shares"

    share_id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
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
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    __table_args__ = (db.UniqueConstraint("file_id", "shared_with"),)

    def __repr__(self) -> str:
        return f"<FileShare {self.share_id}>"
