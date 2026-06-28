from functools import wraps
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from flask import jsonify

def admin_required():
    """
    Decorator to restrict access to Admins only.
    Verifies JWT token identity properties.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request()
                identity = get_jwt_identity()
                if identity and identity.get('role') == 'Admin':
                    return fn(*args, **kwargs)
                return jsonify({"message": "Access denied: Admin role required"}), 403
            except Exception as e:
                return jsonify({"message": "Authentication failed", "details": str(e)}), 401
        return wrapper
    return decorator

def analyst_required():
    """
    Decorator to restrict access to Admins or Security Analysts.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request()
                identity = get_jwt_identity()
                if identity and identity.get('role') in ['Admin', 'Security Analyst']:
                    return fn(*args, **kwargs)
                return jsonify({"message": "Access denied: Security Analyst credentials required"}), 403
            except Exception as e:
                return jsonify({"message": "Authentication failed", "details": str(e)}), 401
        return wrapper
    return decorator
