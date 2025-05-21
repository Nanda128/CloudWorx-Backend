from flask import Blueprint, request, jsonify, current_app
from app import db
from app.models.user import UserLogin, UserKEK
import jwt
import datetime
import os
import uuid
import re
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from functools import wraps
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import secrets

auth_bp = Blueprint('auth', __name__)

def token_required(f):
    """Decorator to check if the request has a valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(' ')[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            jwt_secret = current_app.config['JWT_SECRET_KEY']
            if jwt_secret is None:
                return jsonify({'message': 'JWT secret key is not set in environment variables!'}), 500
            data = jwt.decode(token, jwt_secret, algorithms=["HS256"])
            current_user = UserLogin.query.filter_by(id=data['user_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

def validate_password_strength(password):
    """Validate that password meets complexity requirements"""
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
        
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
        
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
        
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
        
    return True, ""

def validate_base64(value, name):
    """Validate that a value is a valid base64 string"""
    try:
        base64.b64decode(value)
        return True, ""
    except:
        return False, f"Invalid base64 encoding for {name}"

def validate_iv(iv):
    """Validate that IV is correct size (96 bits / 12 bytes)"""
    try:
        decoded = base64.b64decode(iv)
        if len(decoded) != 12:
            return False, "IV must be 96 bits (12 bytes)"
        return True, ""
    except:
        return False, "Invalid IV format"

def validate_argon2id_params(params):
    """Validate Argon2id parameters"""
    if not isinstance(params, list) or len(params) != 3:
        return False, "Argon2id parameters must be an array with 3 elements"
    
    if not all(isinstance(p, int) for p in params):
        return False, "All Argon2id parameters must be integers"
    
    p, m, t = params
    
    if p <= 0 or m <= 0 or t <= 0:
        return False, "Argon2id parameters must be positive"
    
    return True, ""

def handle_error(error, code=500):
    """Handle errors and return a JSON response"""
    return jsonify({'message': str(error)}), code

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    {
        username: String. The desired username for the new user.
        auth_password: String. The user's password (plain text).
        email: String. The user's email address (must be valid format).
        salt: String. Base64-encoded salt used for key derivation.
        iv_KEK: String. Base64-encoded initialization vector for encrypting the KEK.
        encrypted_KEK: String. Base64-encoded encrypted Key Encryption Key.
        verification_code: String. Base64-encoded code for verifying the KEK.
        verification_iv: String. Base64-encoded IV for the verification code.
        argon2id_params: List of three integers. Parameters for Argon2id key derivation (m, p, t).
    }
    """
    data = request.get_json()
    
    required_fields = ['username', 'auth_password', 'email', 'salt', 'iv_KEK', 
                        'encrypted_KEK', 'verification_code', 'verification_iv', 'argon2id_params']
    for field in required_fields:
        if field not in data or not data[field]:
            return handle_error(f'Missing required field: {field}', 400)
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, data['email']):
        return handle_error('Invalid email format', 400)
    
    if UserLogin.query.filter_by(username=data['username']).first():
        return handle_error('Username already exists!', 409)
    
    if UserLogin.query.filter_by(email=data['email']).first():
        return handle_error('Email already exists!', 409)
    
    base64_fields = ['salt', 'iv_KEK', 'encrypted_KEK', 'verification_code', 'verification_iv']
    for field in base64_fields:
        is_valid, error = validate_base64(data[field], field)
        if not is_valid:
            return handle_error(error, 400)
    
    for field in ['iv_KEK', 'verification_iv']:
        is_valid, error = validate_iv(data[field])
        if not is_valid:
            return handle_error(error, 400)
    
    is_valid, error = validate_argon2id_params(data['argon2id_params'])
    if not is_valid:
        return handle_error(error, 400)

    ciphertext = base64.b64decode(data['encrypted_KEK'])
    if not ciphertext:
        return handle_error('Invalid encrypted_KEK format', 400)
    
    auth_p = current_app.config['ARGON2_PARALLELISM']
    auth_m = current_app.config['ARGON2_MEMORY_COST']
    auth_t = current_app.config['ARGON2_TIME_COST']
    
    auth_salt = secrets.token_hex(16)
    
    ph = PasswordHasher(
        time_cost=auth_t,
        memory_cost=auth_m,
        parallelism=auth_p,
        hash_len=32,
        salt_len=16
    )
    auth_password_hash = ph.hash(data['auth_password'], salt=auth_salt.encode())

    user_id = str(uuid.uuid4())
    
    new_user = UserLogin(
        id=user_id,
        username=data['username'],
        auth_password=auth_password_hash,
        email=data['email'],
        auth_salt=auth_salt,
        auth_p=auth_p,
        auth_m=auth_m,
        auth_t=auth_t
    )
    
    new_kek = UserKEK(
        key_id=str(uuid.uuid4()),
        user_id=user_id,
        salt=data['salt'],
        iv_KEK=data['iv_KEK'],
        encrypted_KEK=data['encrypted_KEK'],
        assoc_data_KEK="User Key Encryption Key for " + user_id,
        m=data['argon2id_params'][0],
        p=data['argon2id_params'][1],
        t=data['argon2id_params'][2],
        verification_code=data['verification_code'],
        verification_iv=data['verification_iv']
    )
    
    db.session.add(new_user)
    db.session.add(new_kek)
    db.session.commit()
    
    return jsonify({'message': 'User created successfully!', 'user_id': user_id}), 201

@auth_bp.route('/retrieve-files', methods=['POST'])
def retrieveFiles():
    """
    {
        username: String. The username of the user.
        password_derived_key: String. The derived key from the user's password with Argon2id.
    }
    """
    data = request.get_json()
    
    if 'username' not in data or 'password_derived_key' not in data:
        return handle_error('Missing username or password derived key', 400)

    if not isinstance(data['username'], str) or not isinstance(data['password_derived_key'], str):
        return handle_error('Username and password derived key must be strings', 400)
    
    user = UserLogin.query.filter_by(username=data['username']).first()
    
    if not user:
        return handle_error('User not found!', 404)
    
    kek_data = UserKEK.query.filter_by(user_id=user.id).first()
    
    if not kek_data:
        return handle_error('User KEK not found!', 404)
    
    try:
        password_key = base64.b64decode(data['password_derived_key'])
        
        if not kek_data.encrypted_KEK or not kek_data.iv_KEK:
            return handle_error('Missing KEK or IV for user!', 500)

        encrypted_kek = base64.b64decode(kek_data.encrypted_KEK)
        iv_kek = base64.b64decode(kek_data.iv_KEK)

        try:
            aesgcm = AESGCM(password_key)
            kek = aesgcm.decrypt(iv_kek, encrypted_kek, None)
        except Exception:
            return handle_error('Invalid password!', 401)
        
        verification_iv = base64.b64decode(kek_data.verification_iv)
        verification_code = base64.b64decode(kek_data.verification_code)
        try:
            aesgcm = AESGCM(kek)
            plaintext = aesgcm.decrypt(verification_iv, verification_code, None)
            
            if plaintext.decode('utf-8') != "VERIFICATION_SUCCESS":
                return handle_error('Invalid password!', 401)
        except Exception:
            return handle_error('Invalid password!', 401)
            
    except Exception as e:
        return handle_error('Authentication failed: ' + str(e), 401)
    
    jwt_secret = current_app.config['JWT_SECRET_KEY']
    if jwt_secret is None:
        return handle_error('JWT secret key is not set in environment variables!', 500)

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    }, jwt_secret)
    
    # TODO: Implement file retrieval logic here
    # For now, we will just return a placeholder response
    
    files = [
        {
            'file_id': str(uuid.uuid4()),
            'file_name': 'example.txt',
            'file_size': 12345,
            'file_type': 'text/plain'
        }
    ]
    
    return jsonify({
        'token': token,
        'user_id': user.id,
        'username': user.username,
        'files': files
    }), 200

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    {
        username: String. The username of the user.
        entered_auth_password: String. The authentication password.
    }
    """
    data = request.get_json()
    
    required_fields = ['username', 'entered_auth_password']
    
    for field in required_fields:
        if field not in data:
            return handle_error(f'Missing required field: {field}', 400)

    user = UserLogin.query.filter_by(username=data['username']).first()
    if not user:
        return handle_error('Invalid username or authentication password!', 401)
    
    try:
        ph = PasswordHasher(
            time_cost=user.auth_t,
            memory_cost=user.auth_m,
            parallelism=user.auth_p,
            hash_len=32,
            salt_len=16
        )
        ph.verify(user.auth_password, data['entered_auth_password'])
    except VerifyMismatchError:
        return handle_error('Invalid username or authentication password!', 401)
    
    jwt_secret = current_app.config['JWT_SECRET_KEY']
    if jwt_secret is None:
        return handle_error('JWT secret key is not set in environment variables!', 500)

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    }, jwt_secret)
    
    return jsonify({
        'token': token,
        'user_id': user.id,
        'username': user.username
    }), 200

@auth_bp.route('/auth-password', methods=['PUT'])
@token_required
def change_auth_password():
    """
    {
        username: String. The username of the user.
        old_auth_password: String. The user's old authentication password.
        new_auth_password: String. The user's new authentication password.
    }
    """
    data = request.get_json()
    
    required_fields = ['username', 'old_auth_password', 'new_auth_password']
    
    for field in required_fields:
        if field not in data:
            return handle_error(f'Missing required field: {field}', 400)
    
    user = UserLogin.query.filter_by(username=data['username']).first()
    if not user:
        return handle_error('Invalid username or user not found!', 404)
    
    try:
        ph = PasswordHasher(
            time_cost=user.auth_t,
            memory_cost=user.auth_m,
            parallelism=user.auth_p,
            hash_len=32,
            salt_len=16
        )
        ph.verify(user.auth_password, data['old_auth_password'])
    except VerifyMismatchError:
        return handle_error('Invalid old authentication password!', 401)
    
    if not validate_password_strength(data['new_auth_password'])[0]:
        return handle_error('New authentication password does not meet complexity requirements', 400)
    if data['old_auth_password'] == data['new_auth_password']:
        return handle_error('New authentication password must be different from the old one', 400)
    
    auth_p = current_app.config['ARGON2_PARALLELISM']
    auth_m = current_app.config['ARGON2_MEMORY_COST']
    auth_t = current_app.config['ARGON2_TIME_COST']
    auth_salt = secrets.token_hex(16)
    
    ph = PasswordHasher(
        time_cost=auth_t,
        memory_cost=auth_m,
        parallelism=auth_p,
        hash_len=32,
        salt_len=16
    )
    auth_password_hash = ph.hash(data['new_auth_password'], salt=auth_salt.encode())
    
    user.auth_password = auth_password_hash
    user.auth_salt = auth_salt
    user.auth_p = auth_p
    user.auth_m = auth_m
    user.auth_t = auth_t
    
    db.session.commit()
    
    return jsonify({'message': 'Authentication password changed successfully!'}), 200

@auth_bp.route('/encryption-password', methods=['PUT'])
@token_required
def change_encryption_password():
    """
    {
        username: String. The username of the user.
        old_password_derived_key: String. The derived key from the user's old password with Argon2id.
        new_password_derived_key: String. The derived key from the user's new password with Argon2id.
        new_salt: String. Base64-encoded salt used for key derivation.
        new_iv_KEK: String. Base64-encoded initialization vector for encrypting the KEK.
        new_encrypted_KEK: String. Base64-encoded encrypted Key Encryption Key.
        new_verification_code: String. Base64-encoded code for verifying the KEK.
        new_verification_iv: String. Base64-encoded IV for the verification code.
        new_argon2id_params: List of three integers. Parameters for Argon2id key derivation (m, p, t).
    }
    """
    data = request.get_json()
    
    required_fields = ['username', 'old_password_derived_key', 'new_password_derived_key', 'new_salt', 
                        'new_iv_KEK', 'new_encrypted_KEK', 'new_verification_code', 
                        'new_verification_iv', 'new_argon2id_params']
    
    user = UserLogin.query.filter_by(username=data['username']).first()
    if not user:
        return handle_error('User not found!', 404)
    user_id = user.id
    
    for field in required_fields:
        if field not in data:
            return handle_error(f'Missing required field: {field}', 400)
    
    base64_fields = ['old_password_derived_key', 'new_salt', 'new_iv_KEK', 'new_encrypted_KEK', 
                    'new_verification_code', 'new_verification_iv']
    for field in base64_fields:
        is_valid, error = validate_base64(data[field], field)
        if not is_valid:
            return handle_error(error, 400)
    
    for field in ['new_iv_KEK', 'new_verification_iv']:
        is_valid, error = validate_iv(data[field])
        if not is_valid:
            return handle_error(error, 400)
    
    is_valid, error = validate_argon2id_params(data['new_argon2id_params'])
    if not is_valid:
        return handle_error(error, 400)
    
    kek_data = UserKEK.query.filter_by(user_id=user_id).first()
    if not kek_data:
        return handle_error('User KEK not found!', 404)
    
    try:
        old_password_key = base64.b64decode(data['old_password_derived_key'])
        encrypted_kek = base64.b64decode(kek_data.encrypted_KEK)
        iv_kek = base64.b64decode(kek_data.iv_KEK)
        
        try:
            aesgcm = AESGCM(old_password_key)
            old_kek = aesgcm.decrypt(iv_kek, encrypted_kek, None)
        except Exception:
            return handle_error('Invalid old password!', 401)
        
        verification_iv = base64.b64decode(kek_data.verification_iv)
        verification_code = base64.b64decode(kek_data.verification_code)
        
        try:
            aesgcm = AESGCM(old_kek)
            plaintext = aesgcm.decrypt(verification_iv, verification_code, None)
            
            if plaintext.decode('utf-8') != "VERIFICATION_SUCCESS":
                return handle_error('Invalid old password!', 401)
        except Exception:
            return handle_error('Invalid old password!', 401)
    except Exception as e:
        return handle_error('Authentication failed: ' + str(e), 401)
    
    kek_data.salt = data['new_salt']
    kek_data.iv_KEK = data['new_iv_KEK']
    kek_data.encrypted_KEK = data['new_encrypted_KEK']
    kek_data.p = data['new_argon2id_params'][0]
    kek_data.m = data['new_argon2id_params'][1]
    kek_data.t = data['new_argon2id_params'][2]
    kek_data.verification_code = data['new_verification_code']
    kek_data.verification_iv = data['new_verification_iv']
    
    db.session.commit()
    
    return jsonify({'message': 'Encryption password changed successfully!'}), 200