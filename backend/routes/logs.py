from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from config.db import get_db
from models.database import init_log, init_audit_log
from services.geoip import lookup_geoip
from services.alert_engine import process_log_correlation
from services.socket_service import emit_log
from middleware.security import admin_required, analyst_required

logs_bp = Blueprint('logs', __name__)

def auto_classify_severity(event_type, status):
    """Smart Threat Severity Classification (Feature 9)."""
    evt = event_type.lower()
    stat = status.lower()
    
    if any(k in evt for k in ['rce', 'exploit', 'malware', 'ddos', 'backdoor']):
        return 'Critical'
    if any(k in evt for k in ['brute_force', 'sql_injection', 'port_scan', 'attack', 'compromise']):
        return 'High'
    if stat == 'failure' or any(k in evt for k in ['failed', 'unauthorized', 'suspicious', 'blocked', 'denied']):
        return 'Medium'
    if any(k in evt for k in ['login_success', 'access', 'query', 'start', 'reboot', 'reconnect']):
        return 'Low'
    return 'Informational'

@logs_bp.route('', methods=['POST'])
def ingest_log():
    db = get_db()
    data = request.get_json() or {}
    
    source = data.get('source', '').strip()
    event_type = data.get('event_type', '').strip()
    ip_address = data.get('ip_address', '').strip()
    message = data.get('message', '').strip()
    status = data.get('status', 'success').strip()
    username = data.get('username', '').strip()
    severity = data.get('severity', '').strip()
    
    if not source or not event_type or not ip_address or not message:
        return jsonify({"message": "Source, event_type, ip_address, and message are required"}), 400
        
    # Auto-classify severity if not provided (Feature 9)
    if not severity:
        severity = auto_classify_severity(event_type, status)
        
    # GeoIP Tracking (Feature 2)
    country, city = lookup_geoip(ip_address)
    
    try:
        log_doc = init_log(
            source=source,
            event_type=event_type,
            severity=severity,
            ip_address=ip_address,
            username=username if username else None,
            message=message,
            status=status,
            country=country,
            city=city
        )
        
        res = db.logs.insert_one(log_doc)
        log_doc['_id'] = str(res.inserted_id)
        
        # Correlate via Alert correlation engine
        process_log_correlation(log_doc)
        
        # Broadcast over Websockets
        emit_log(log_doc)
        
        return jsonify(log_doc), 201
    except Exception as e:
        return jsonify({"message": "Error ingesting security log", "details": str(e)}), 500

@logs_bp.route('', methods=['GET'])
@jwt_required()
def get_logs():
    db = get_db()
    
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 50))
    skip = (page - 1) * limit
    
    # Query filters (Feature 3: Log Search Filters)
    query = {}
    
    severity = request.args.get('severity')
    event_type = request.args.get('event_type')
    source = request.args.get('source')
    ip_address = request.args.get('ip_address')
    username = request.args.get('username')
    start_date = request.args.get('startDate') or request.args.get('start_date')
    end_date = request.args.get('endDate') or request.args.get('end_date')
    search = request.args.get('search')
    
    if severity:
        query['severity'] = severity
    if event_type:
        query['event_type'] = event_type
    if source:
        query['source'] = source
    if ip_address:
        query['ip_address'] = ip_address
    if username:
        query['username'] = username
        
    # Date Range filtering
    if start_date or end_date:
        query['timestamp'] = {}
        if start_date:
            query['timestamp']['$gte'] = start_date
        if end_date:
            query['timestamp']['$lte'] = end_date
            
    # Search keyword filtering
    if search:
        # If fallback mode is active, our FallbackCollection handles $or mapping locally
        query['$or'] = [
            {"message": {"$regex": search}},
            {"ip_address": {"$regex": search}},
            {"source": {"$regex": search}},
            {"event_type": {"$regex": search}}
        ]
        
    try:
        total = db.logs.count_documents(query)
        logs = db.logs.find(
            query,
            sort=[('timestamp', -1)],
            skip=skip,
            limit=limit
        )
        
        # Convert cursors to lists and stringify ObjectIds
        logs_list = []
        for l in logs:
            l['_id'] = str(l['_id'])
            logs_list.append(l)
            
        return jsonify({
            "logs": logs_list,
            "page": page,
            "pages": (total + limit - 1) // limit,
            "total": total
        }), 200
    except Exception as e:
        return jsonify({"message": "Error fetching security logs", "details": str(e)}), 500

@logs_bp.route('/search', methods=['GET'])
@jwt_required()
def search_logs():
    # Mapping logs search directly to general get_logs for compliance with route mappings
    return get_logs()

@logs_bp.route('/<id>', methods=['PUT'])
@analyst_required()
def update_log(id):
    db = get_db()
    data = request.get_json() or {}
    
    # Restrict keys that can be updated
    allowed_keys = ['severity', 'message', 'status']
    update_data = {k: v for k, v in data.items() if k in allowed_keys}
    
    if not update_data:
        return jsonify({"message": "No valid fields to update"}), 400
        
    try:
        res = db.logs.update_one({"_id": id}, {"$set": update_data})
        if res.modified_count == 0:
            # Fallback search if ObjectId mismatch in live MongoDB
            from bson import ObjectId
            try:
                res = db.logs.update_one({"_id": ObjectId(id)}, {"$set": update_data})
            except:
                pass
                
        # Log event in Audit Logs
        identity = get_jwt_identity()
        username = identity.get('username')
        client_ip = request.remote_addr or '127.0.0.1'
        db.audit_logs.insert_one(init_audit_log(
            user=username,
            action="Log Changes",
            ip_address=client_ip,
            details=f"Log ID {id} updated: {update_data}"
        ))
        
        return jsonify({"message": "Log updated successfully"}), 200
    except Exception as e:
        return jsonify({"message": "Error updating security log", "details": str(e)}), 500

@logs_bp.route('/<id>', methods=['DELETE'])
@admin_required()
def delete_log(id):
    db = get_db()
    try:
        res = db.logs.delete_one({"_id": id})
        if res.deleted_count == 0:
            from bson import ObjectId
            try:
                res = db.logs.delete_one({"_id": ObjectId(id)})
            except:
                pass
                
        # Log in Audit Logs
        identity = get_jwt_identity()
        username = identity.get('username')
        client_ip = request.remote_addr or '127.0.0.1'
        db.audit_logs.insert_one(init_audit_log(
            user=username,
            action="Log Changes",
            ip_address=client_ip,
            details=f"Log ID {id} deleted from databases"
        ))
        
        return jsonify({"message": "Log deleted successfully"}), 200
    except Exception as e:
        return jsonify({"message": "Error deleting security log", "details": str(e)}), 500
stream_logs = logs_bp
