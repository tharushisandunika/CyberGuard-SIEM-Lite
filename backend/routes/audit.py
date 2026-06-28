from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from config.db import get_db
from middleware.security import analyst_required

audit_bp = Blueprint('audit', __name__)

@audit_bp.route('', methods=['GET'])
@jwt_required()
def get_audit_logs():
    db = get_db()
    try:
        audit_logs = db.audit_logs.find({}, sort=[('timestamp', -1)])
        logs_list = []
        for l in audit_logs:
            l['_id'] = str(l['_id'])
            logs_list.append(l)
        return jsonify(logs_list), 200
    except Exception as e:
        return jsonify({"message": "Error fetching audit logs", "details": str(e)}), 500
