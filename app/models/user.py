from app import db
from datetime import datetime, timezone

class UserLogin(db.Model):
    __tablename__ = 'user_login'
    
    id = db.Column(db.String(36), primary_key=True, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    auth_password = db.Column(db.String(255), nullable=False)
    auth_salt = db.Column(db.String(255), nullable=False)
    auth_p = db.Column(db.Integer, nullable=False)
    auth_m = db.Column(db.Integer, nullable=False)
    auth_t = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    modified_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    kek = db.relationship('UserKEK', backref='user', uselist=False, cascade='all, delete-orphan')
    files = db.relationship('File', backref='owner', lazy=True, foreign_keys='File.created_by')
    shared_files = db.relationship('FileShare', backref='recipient', lazy=True, foreign_keys='FileShare.shared_with')
    
    def __init__(self, id, username, auth_password, email, auth_salt, auth_p, auth_m, auth_t):
        self.id = id
        self.username = username
        self.auth_password = auth_password
        self.email = email
        self.auth_salt = auth_salt
        self.auth_p = auth_p
        self.auth_m = auth_m
        self.auth_t = auth_t
    
    def __repr__(self):
        return f'<User {self.username}>'

class UserKEK(db.Model):
    __tablename__ = 'user_kek'
    
    key_id = db.Column(db.String(36), primary_key=True, nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('user_login.id', ondelete='CASCADE'), nullable=False)
    salt = db.Column(db.String(255), nullable=False)
    iv_KEK = db.Column(db.String(255), nullable=False)
    encrypted_KEK = db.Column(db.String(255), nullable=False)
    assoc_data_KEK = db.Column(db.String(255), nullable=False)
    p = db.Column(db.Integer, nullable=False)
    m = db.Column(db.Integer, nullable=False)
    t = db.Column(db.Integer, nullable=False)
    verification_code = db.Column(db.String(255), nullable=False)
    verification_iv = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    
    def __init__(self, key_id, user_id, salt, iv_KEK, encrypted_KEK, assoc_data_KEK, p, m, t, verification_code, verification_iv):
        self.key_id = key_id
        self.user_id = user_id
        self.salt = salt
        self.iv_KEK = iv_KEK
        self.encrypted_KEK = encrypted_KEK
        self.assoc_data_KEK = assoc_data_KEK
        self.p = p
        self.m = m
        self.t = t
        self.verification_code = verification_code
        self.verification_iv = verification_iv
    
    def __repr__(self):
        return f'<UserKEK {self.key_id}>'
