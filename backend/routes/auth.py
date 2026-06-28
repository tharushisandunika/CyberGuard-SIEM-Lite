from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from config.db import get_db
from models.database import init_user, init_audit_log, check_password
import datetime

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    db = get_db()
    data = request.get_json() or {}
    
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'Security Analyst').strip()
    
    if not username or not email or not password:
        return jsonify({"message": "Username, email, and password are required"}), 400
        
    if role not in ['Admin', 'Security Analyst']:
        return jsonify({"message": "Invalid role specified"}), 400
        
    # Check if user already exists
    if db.users.find_one({"username": username}) or db.users.find_one({"email": email.lower()}):
        return jsonify({"message": "User with this username or email already exists"}), 400
        
    try:
        user_doc = init_user(username, email, password, role)
        res = db.users.insert_one(user_doc)
        user_id = str(res.inserted_id)
        
        # Log event in Audit Logs (Requirement: Audit Logging Module)
        client_ip = request.remote_addr or '127.0.0.1'
        db.audit_logs.insert_one(init_audit_log(
            user=username,
            action="User Changes",
            ip_address=client_ip,
            details=f"Analyst account registered successfully with role: {role}"
        ))
        
        # Create token
        identity = {"id": user_id, "username": username, "role": role}
        token = create_access_token(identity=identity, expires_delta=datetime.timedelta(hours=24))
        
        return jsonify({
            "_id": user_id,
            "username": username,
            "email": email,
            "role": role,
            "token": token
        }), 201
    except Exception as e:
        return jsonify({"message": "Error creating analyst account", "details": str(e)}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    db = get_db()
    data = request.get_json() or {}
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400
        
    user = db.users.find_one({"username": username})
    if not user:
        client_ip = request.remote_addr or '127.0.0.1'
        db.audit_logs.insert_one(init_audit_log(
            user=username,
            action="Login Attempts",
            ip_address=client_ip,
            details="Failed login attempt: invalid username"
        ))
        return jsonify({"message": "Invalid username or password"}), 401
        
    is_valid = check_password(password, user['password_hash'])
    if not is_valid:
        client_ip = request.remote_addr or '127.0.0.1'
        db.audit_logs.insert_one(init_audit_log(
            user=username,
            action="Login Attempts",
            ip_address=client_ip,
            details="Failed login attempt: invalid password"
        ))
        return jsonify({"message": "Invalid username or password"}), 401
        
    user_id = str(user.get('_id') or user.get('id'))
    role = user.get('role')
    
    # Audit log
    client_ip = request.remote_addr or '127.0.0.1'
    db.audit_logs.insert_one(init_audit_log(
        user=username,
        action="Login Attempts",
        ip_address=client_ip,
        details="Successful user authentication"
    ))
    
    identity = {"id": user_id, "username": username, "role": role}
    token = create_access_token(identity=identity, expires_delta=datetime.timedelta(hours=24))
    
    return jsonify({
        "_id": user_id,
        "username": username,
        "email": user.get('email'),
        "role": role,
        "token": token
    }), 200

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    db = get_db()
    identity = get_jwt_identity()
    username = identity.get('username')
    
    client_ip = request.remote_addr or '127.0.0.1'
    db.audit_logs.insert_one(init_audit_log(
        user=username,
        action="Login Attempts",
        ip_address=client_ip,
        details="User logged out of session"
    ))
    
    return jsonify({"message": "Logout successful"}), 200
