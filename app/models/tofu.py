import uuid
from datetime import datetime, timezone
from enum import Enum

from app import db


class TrustStatus(Enum):
    TRUSTED = "trusted"
    REVOKED = "revoked"
    SUSPICIOUS = "suspicious"


class TrustedKey(db.Model):
    __tablename__ = "trusted_keys"

    id = db.Column(db.String(36), primary_key=True, nullable=False)
    user_id = db.Column(
        db.String(36),
        db.ForeignKey("user_login.id", ondelete="CASCADE"),
        nullable=False,
    )
    key_fingerprint = db.Column(db.String(64), nullable=False, index=True)
    public_key = db.Column(db.Text, nullable=False)
    first_seen = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    last_verified = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    trust_status = db.Column(db.Enum(TrustStatus), default=TrustStatus.TRUSTED)
    verification_count = db.Column(db.Integer, default=1)

    __table_args__ = (db.UniqueConstraint("user_id", "key_fingerprint", name="unique_user_key"),)

    def __init__(self, user_id: str, key_fingerprint: str, public_key: str) -> None:
        self.id = str(uuid.uuid4())
        self.user_id = user_id
        self.key_fingerprint = key_fingerprint
        self.public_key = public_key

    def mark_verified(self) -> None:
        self.last_verified = datetime.now(timezone.utc)
        self.verification_count += 1

    def __repr__(self) -> str:
        return f"<TrustedKey {self.key_fingerprint[:16]}...>"
