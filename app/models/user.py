from datetime import datetime, timezone  # noqa: INP001
from typing import NamedTuple

from app import db


class UserLogin(db.Model):
    __tablename__ = "user_login"

    id = db.Column(db.String(36), primary_key=True, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    auth_password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    modified_at = db.Column(
        db.DateTime,
        default=datetime.now(timezone.utc),
        onupdate=datetime.now(timezone.utc),
    )

    kek = db.relationship(
        "UserKEK",
        backref="user",
        uselist=False,
        cascade="all, delete-orphan",
    )
    files = db.relationship(
        "File",
        backref="owner",
        lazy=True,
        foreign_keys="File.created_by",
    )
    shared_files = db.relationship(
        "FileShare",
        backref="recipient",
        lazy=True,
        foreign_keys="FileShare.shared_with",
    )

    def __init__(
        self,
        user_id: str,
        username: str,
        email: str,
        password: str,
    ) -> None:
        self.id = user_id
        self.username = username
        self.auth_password = password
        self.email = email

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class UserKEK(db.Model):
    __tablename__ = "user_kek"

    key_id = db.Column(db.String(36), primary_key=True, nullable=False)
    user_id = db.Column(
        db.String(36),
        db.ForeignKey("user_login.id", ondelete="CASCADE"),
        nullable=False,
    )
    iv_kek = db.Column(db.String(255), nullable=False)
    encrypted_kek = db.Column(db.String(255), nullable=False)
    assoc_data_kek = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    class KEKParams(NamedTuple):
        iv_kek: str
        encrypted_kek: str
        assoc_data_kek: str

    def __init__(
        self,
        key_id: str,
        user_id: str,
        kek_params: "UserKEK.KEKParams",
    ) -> None:
        self.key_id = key_id
        self.user_id = user_id
        self.iv_kek = kek_params.iv_kek
        self.encrypted_kek = kek_params.encrypted_kek
        self.assoc_data_kek = kek_params.assoc_data_kek

    def __repr__(self) -> str:
        return f"<UserKEK {self.key_id}>"
