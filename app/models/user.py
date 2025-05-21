from dataclasses import dataclass  # noqa: INP001
from datetime import datetime, timezone
from typing import NamedTuple

from app import db


class UserLogin(db.Model):
    __tablename__ = "user_login"

    id = db.Column(db.String(36), primary_key=True, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    auth_password = db.Column(db.String(255), nullable=False)
    auth_salt = db.Column(db.String(255), nullable=False)
    auth_p = db.Column(db.Integer, nullable=False)
    auth_m = db.Column(db.Integer, nullable=False)
    auth_t = db.Column(db.Integer, nullable=False)
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

    @dataclass
    class AuthParams:
        password: str
        salt: str
        p: int
        m: int
        t: int

    def __init__(
        self,
        user_id: str,
        username: str,
        email: str,
        auth_params: "UserLogin.AuthParams",
    ) -> None:
        self.id = user_id
        self.username = username
        self.auth_password = auth_params.password
        self.email = email
        self.auth_salt = auth_params.salt
        self.auth_p = auth_params.p
        self.auth_m = auth_params.m
        self.auth_t = auth_params.t

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
    salt = db.Column(db.String(255), nullable=False)
    iv_kek = db.Column(db.String(255), nullable=False)
    encrypted_kek = db.Column(db.String(255), nullable=False)
    assoc_data_kek = db.Column(db.String(255), nullable=False)
    p = db.Column(db.Integer, nullable=False)
    m = db.Column(db.Integer, nullable=False)
    t = db.Column(db.Integer, nullable=False)
    verification_code = db.Column(db.String(255), nullable=False)
    verification_iv = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    class KEKParams(NamedTuple):
        salt: str
        iv_kek: str
        encrypted_kek: str
        assoc_data_kek: str
        p: int
        m: int
        t: int
        verification_code: str
        verification_iv: str

    def __init__(
        self,
        key_id: str,
        user_id: str,
        kek_params: "UserKEK.KEKParams",
    ) -> None:
        self.key_id = key_id
        self.user_id = user_id
        self.salt = kek_params.salt
        self.iv_kek = kek_params.iv_kek
        self.encrypted_kek = kek_params.encrypted_kek
        self.assoc_data_kek = kek_params.assoc_data_kek
        self.p = kek_params.p
        self.m = kek_params.m
        self.t = kek_params.t
        self.verification_code = kek_params.verification_code
        self.verification_iv = kek_params.verification_iv

    def __repr__(self) -> str:
        return f"<UserKEK {self.key_id}>"
