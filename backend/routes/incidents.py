from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from config.db import get_db
from models.database import init_incident, init_audit_log
from middleware.security import admin_required, analyst_required
import datetime

incidents_bp = Blueprint('incidents', __name__)

@incidents_bp.route('', methods=['POST'])
@analyst_required()
def create_incident():
    db = get_db()
    data = request.get_json() or {}
    
    title = data.get('title', '').strip()
    description = data.get('description', '').strip()
    severity = data.get('severity', '').strip()
    assigned_to = data.get('assigned_to', '').strip()
    status = data.get('status', 'Open').strip()
    
    if not title or not description or not severity:
        return jsonify({"message": "Title, description, and severity are required"}), 400
        
    if severity not in ['Informational', 'Low', 'Medium', 'High', 'Critical']:
        return jsonify({"message": "Invalid severity level specified"}), 400
        
    if status not in ['Open', 'Investigating', 'Resolved', 'Closed']:
        return jsonify({"message": "Invalid status specified"}), 400
        
    try:
        incident_doc = init_incident(
            title=title,
            description=description,
            severity=severity,
            assigned_to=assigned_to if assigned_to else None,
            status=status
        )
        res = db.incidents.insert_one(incident_doc)
        incident_doc['_id'] = str(res.inserted_id)
        
        # Log in Audit Logs
        identity = get_jwt_identity()
        username = identity.get('username')
        client_ip = request.remote_addr or '127.0.0.1'
        db.audit_logs.insert_one(init_audit_log(
            user=username,
            action="Incident Changes",
            ip_address=client_ip,
            details=f"Incident '{title}' manually generated (Severity: {severity})"
        ))
        
        return jsonify(incident_doc), 201
    except Exception as e:
        return jsonify({"message": "Error creating incident", "details": str(e)}), 500

@incidents_bp.route('', methods=['GET'])
@jwt_required()
def get_incidents():
    db = get_db()
    
    query = {}
    severity = request.args.get('severity')
    status = request.args.get('status')
    assigned_to = request.args.get('assigned_to')
    
    if severity:
        query['severity'] = severity
    if status:
        query['status'] = status
    if assigned_to:
        query['assigned_to'] = assigned_to
        
    try:
        incidents = db.incidents.find(query, sort=[('created_at', -1)])
        incidents_list = []
        for i in incidents:
            i['_id'] = str(i['_id'])
            incidents_list.append(i)
        return jsonify(incidents_list), 200
    except Exception as e:
        return jsonify({"message": "Error retrieving incidents list", "details": str(e)}), 500

@incidents_bp.route('/<id>', methods=['PUT'])
@analyst_required()
def update_incident(id):
    db = get_db()
    data = request.get_json() or {}
    
    title = data.get('title')
    description = data.get('description')
    severity = data.get('severity')
    assigned_to = data.get('assigned_to')
    status = data.get('status')
    
    update_data = {}
    if title:
        update_data['title'] = title.strip()
    if description:
        update_data['description'] = description.strip()
    if severity:
        if severity not in ['Informational', 'Low', 'Medium', 'High', 'Critical']:
            return jsonify({"message": "Invalid severity level"}), 400
        update_data['severity'] = severity
    if assigned_to is not None:
        update_data['assigned_to'] = assigned_to.strip() if assigned_to else None
    if status:
        if status not in ['Open', 'Investigating', 'Resolved', 'Closed']:
            return jsonify({"message": "Invalid status level"}), 400
        update_data['status'] = status
        
    if not update_data:
        return jsonify({"message": "No valid fields to update"}), 400
        
    update_data['updated_at'] = datetime.datetime.utcnow().isoformat()
    
    try:
        # Check incident
        incident = db.incidents.find_one({"_id": id})
        if not incident:
            from bson import ObjectId
            try:
                incident = db.incidents.find_one({"_id": ObjectId(id)})
            except:
                pass
        if not incident:
            return jsonify({"message": "Incident not found"}), 404
            
        incident_id = str(incident.get('_id') or incident.get('id'))
        
        # Perform update
        res = db.incidents.update_one({"_id": incident_id}, {"$set": update_data})
        if res.modified_count == 0:
            from bson import ObjectId
            db.incidents.update_one({"_id": ObjectId(incident_id)}, {"$set": update_data})
            
        # Log in Audit Logs
        identity = get_jwt_identity()
        username = identity.get('username')
        client_ip = request.remote_addr or '127.0.0.1'
        db.audit_logs.insert_one(init_audit_log(
            user=username,
            action="Incident Changes",
            ip_address=client_ip,
            details=f"Incident ID {incident_id} updated: {update_data}"
        ))
        
        updated_doc = db.incidents.find_one({"_id": incident_id})
        if not updated_doc:
            from bson import ObjectId
            updated_doc = db.incidents.find_one({"_id": ObjectId(incident_id)})
        updated_doc['_id'] = str(updated_doc['_id'])
        
        return jsonify(updated_doc), 200
    except Exception as e:
        return jsonify({"message": "Error updating incident", "details": str(e)}), 500

@incidents_bp.route('/<id>', methods=['DELETE'])
@admin_required()
def delete_incident(id):
    db = get_db()
    try:
        # Check incident
        incident = db.incidents.find_one({"_id": id})
        if not incident:
            from bson import ObjectId
            try:
                incident = db.incidents.find_one({"_id": ObjectId(id)})
            except:
                pass
        if not incident:
            return jsonify({"message": "Incident not found"}), 404
            
        incident_id = str(incident.get('_id') or incident.get('id'))
        
        # Perform delete
        res = db.incidents.delete_one({"_id": incident_id})
        if res.deleted_count == 0:
            from bson import ObjectId
            db.incidents.delete_one({"_id": ObjectId(incident_id)})
            
        # Log in Audit Logs
        identity = get_jwt_identity()
        username = identity.get('username')
        client_ip = request.remote_addr or '127.0.0.1'
        db.audit_logs.insert_one(init_audit_log(
            user=username,
            action="Incident Changes",
            ip_address=client_ip,
            details=f"Incident ID {incident_id} deleted from databases"
        ))
        
        return jsonify({"message": "Incident deleted successfully"}), 200
    except Exception as e:
        return jsonify({"message": "Error deleting incident", "details": str(e)}), 500
