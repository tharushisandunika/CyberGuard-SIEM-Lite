from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from config.db import get_db
from models.database import init_audit_log
from middleware.security import admin_required, analyst_required

alerts_bp = Blueprint('alerts', __name__)

@alerts_bp.route('', methods=['GET'])
@jwt_required()
def get_alerts():
    db = get_db()
    
    query = {}
    severity = request.args.get('severity')
    status = request.args.get('status')
    source_ip = request.args.get('source_ip')
    
    if severity:
        query['severity'] = severity
    if status:
        query['status'] = status
    if source_ip:
        query['source_ip'] = source_ip
        
    try:
        alerts = db.alerts.find(query, sort=[('created_at', -1)])
        alerts_list = []
        for a in alerts:
            a['_id'] = str(a['_id'])
            alerts_list.append(a)
        return jsonify(alerts_list), 200
    except Exception as e:
        return jsonify({"message": "Error retrieving correlation alerts", "details": str(e)}), 500

@alerts_bp.route('/<id>', methods=['PUT'])
@analyst_required()
def update_alert(id):
    db = get_db()
    data = request.get_json() or {}
    
    status = data.get('status')
    assigned_to = data.get('assigned_to')
    
    update_data = {}
    if status:
        if status not in ['Open', 'Investigating', 'Resolved', 'Closed']:
            return jsonify({"message": "Invalid alert status specified"}), 400
        update_data['status'] = status
    if assigned_to is not None:
        update_data['assigned_to'] = assigned_to.strip()
        
    if not update_data:
        return jsonify({"message": "No valid fields to update"}), 400
        
    try:
        # Check if alert exists
        alert = db.alerts.find_one({"_id": id})
        if not alert:
            from bson import ObjectId
            try:
                alert = db.alerts.find_one({"_id": ObjectId(id)})
            except:
                pass
        if not alert:
            return jsonify({"message": "Alert not found"}), 404
            
        alert_id = str(alert.get('_id') or alert.get('id'))
        
        # Perform update
        res = db.alerts.update_one({"_id": alert_id}, {"$set": update_data})
        if res.modified_count == 0:
            from bson import ObjectId
            db.alerts.update_one({"_id": ObjectId(alert_id)}, {"$set": update_data})
            
        # Log event in Audit Logs
        identity = get_jwt_identity()
        username = identity.get('username')
        client_ip = request.remote_addr or '127.0.0.1'
        db.audit_logs.insert_one(init_audit_log(
            user=username,
            action="Alert Changes",
            ip_address=client_ip,
            details=f"Alert ID {alert_id} status updated to: {status}"
        ))
        
        # Return updated alert doc
        updated_alert = db.alerts.find_one({"_id": alert_id})
        if not updated_alert:
            from bson import ObjectId
            updated_alert = db.alerts.find_one({"_id": ObjectId(alert_id)})
        updated_alert['_id'] = str(updated_alert['_id'])
        
        return jsonify(updated_alert), 200
    except Exception as e:
        return jsonify({"message": "Error updating alert status", "details": str(e)}), 500

@alerts_bp.route('/<id>', methods=['DELETE'])
@admin_required()
def delete_alert(id):
    db = get_db()
    try:
        # Check alert
        alert = db.alerts.find_one({"_id": id})
        if not alert:
            from bson import ObjectId
            try:
                alert = db.alerts.find_one({"_id": ObjectId(id)})
            except:
                pass
        if not alert:
            return jsonify({"message": "Alert not found"}), 404
            
        alert_id = str(alert.get('_id') or alert.get('id'))
        
        # Perform delete
        res = db.alerts.delete_one({"_id": alert_id})
        if res.deleted_count == 0:
            from bson import ObjectId
            db.alerts.delete_one({"_id": ObjectId(alert_id)})
            
        # Log in Audit Logs
        identity = get_jwt_identity()
        username = identity.get('username')
        client_ip = request.remote_addr or '127.0.0.1'
        db.audit_logs.insert_one(init_audit_log(
            user=username,
            action="Alert Changes",
            ip_address=client_ip,
            details=f"Alert ID {alert_id} deleted from database"
        ))
        
        return jsonify({"message": "Alert deleted successfully"}), 200
    except Exception as e:
        return jsonify({"message": "Error deleting alert", "details": str(e)}), 500
