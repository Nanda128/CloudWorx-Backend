from app import db
import uuid
from datetime import datetime, timezone

class File(db.Model):
    __tablename__ = 'files'
    
    file_id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    file_name = db.Column(db.String(255), nullable=False)
    iv_file = db.Column(db.String(255), nullable=False)
    encrypted_file = db.Column(db.LargeBinary, nullable=False)
    assoc_data_file = db.Column(db.String(255), nullable=False)
    created_by = db.Column(db.String(36), db.ForeignKey('user_login.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    
    dek = db.relationship('FileDEK', backref='file', uselist=False, cascade='all, delete-orphan')
    shares = db.relationship('FileShare', backref='file', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<File {self.file_name}>'

class FileDEK(db.Model):
    __tablename__ = 'file_dek'
    
    key_id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    file_id = db.Column(db.String(36), db.ForeignKey('files.file_id', ondelete='CASCADE'), nullable=False)
    salt = db.Column(db.String(255), nullable=False)
    iv_dek = db.Column(db.String(255), nullable=False)
    encrypted_dek = db.Column(db.String(255), nullable=False)
    assoc_data_dek = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<FileDEK {self.key_id}>'
