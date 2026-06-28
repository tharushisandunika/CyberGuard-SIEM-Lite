from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from config.db import get_db
from models.database import init_log, init_audit_log
from services.geoip import lookup_geoip
from services.alert_engine import process_log_correlation
from services.socket_service import emit_log
from middleware.security import analyst_required
import datetime
import time

simulator_bp = Blueprint('simulator', __name__)

@simulator_bp.route('/brute-force', methods=['POST'])
@analyst_required()
def simulate_brute_force():
    db = get_db()
    source_ip = '198.51.100.101'
    destination = 'Active Directory DC'
    username = request.get_json().get('username', 'administrator')
    
    country, city = lookup_geoip(source_ip)
    logs_inserted = []
    
    try:
        now = datetime.datetime.utcnow()
        for i in range(5):
            # Stagger logs within a 2-second window (fits 10s condition easily)
            log_time = (now - datetime.timedelta(seconds=(5 - i))).isoformat()
            log_doc = init_log(
                source=destination,
                event_type="LOGIN_FAILED",
                severity="Medium",
                ip_address=source_ip,
                username=username,
                message=f"Failed login attempt for user '{username}' (Access denied)",
                status="failure",
                country=country,
                city=city,
                timestamp=log_time
            )
            res = db.logs.insert_one(log_doc)
            log_doc['_id'] = str(res.inserted_id)
            
            # Run engine & websocket emit
            process_log_correlation(log_doc)
            emit_log(log_doc)
            logs_inserted.append(log_doc)
            
        # Log simulator action in audit trail
        identity = get_jwt_identity()
        db.audit_logs.insert_one(init_audit_log(
            user=identity.get('username'),
            action="Incident Changes",
            ip_address=request.remote_addr or '127.0.0.1',
            details=f"Simulated brute force attack from IP {source_ip} targeting user '{username}'"
        ))
        
        return jsonify({
            "message": "SSH Brute force attack simulation completed.",
            "source_ip": source_ip,
            "target": destination,
            "logs_inserted_count": len(logs_inserted),
            "logs": logs_inserted
        }), 201
    except Exception as e:
        return jsonify({"message": "Simulation failed", "details": str(e)}), 500

@simulator_bp.route('/port-scan', methods=['POST'])
@analyst_required()
def simulate_port_scan():
    db = get_db()
    source_ip = '203.0.113.50'
    destination = 'Internal Subnet host 10.0.4.155'
    
    ports = [21, 22, 23, 25, 53, 80, 110, 443, 3389, 8080]
    country, city = lookup_geoip(source_ip)
    logs_inserted = []
    
    try:
        now = datetime.datetime.utcnow()
        for i, port in enumerate(ports):
            log_time = (now - datetime.timedelta(seconds=(10 - i) * 0.2)).isoformat() # spaced 200ms
            log_doc = init_log(
                source="Palo Alto Firewall",
                event_type="PORT_CONNECTION",
                severity="Low",
                ip_address=source_ip,
                username=None,
                message=f"Connection attempt on TCP port {port}",
                status="failure",
                country=country,
                city=city,
                timestamp=log_time
            )
            res = db.logs.insert_one(log_doc)
            log_doc['_id'] = str(res.inserted_id)
            
            process_log_correlation(log_doc)
            emit_log(log_doc)
            logs_inserted.append(log_doc)
            
        # Log simulator action in audit trail
        identity = get_jwt_identity()
        db.audit_logs.insert_one(init_audit_log(
            user=identity.get('username'),
            action="Incident Changes",
            ip_address=request.remote_addr or '127.0.0.1',
            details=f"Simulated TCP Port Scan attack from IP {source_ip}"
        ))
        
        return jsonify({
            "message": "Nmap TCP stealth port scan simulation completed.",
            "source_ip": source_ip,
            "ports_scanned_count": len(logs_inserted),
            "logs": logs_inserted
        }), 201
    except Exception as e:
        return jsonify({"message": "Simulation failed", "details": str(e)}), 500

@simulator_bp.route('/suspicious-login', methods=['POST'])
@analyst_required()
def simulate_suspicious_login():
    db = get_db()
    source_ip = '192.0.2.75'
    destination = 'Linux Core Server'
    username = request.get_json().get('username', 'root')
    
    country, city = lookup_geoip(source_ip)
    logs_inserted = []
    
    try:
        # Override timestamp to 3:30 AM today to trigger rule 3 (abnormal hours)
        now = datetime.datetime.utcnow()
        login_time = datetime.datetime(now.year, now.month, now.day, 3, 30, 0)
        
        log_doc = init_log(
            source=destination,
            event_type="LOGIN_SUCCESS",
            severity="Low",
            ip_address=source_ip,
            username=username,
            message=f"Successful login for user '{username}'",
            status="success",
            country=country,
            city=city,
            timestamp=login_time.isoformat()
        )
        res = db.logs.insert_one(log_doc)
        log_doc['_id'] = str(res.inserted_id)
        
        process_log_correlation(log_doc)
        emit_log(log_doc)
        logs_inserted.append(log_doc)
        
        # Log simulator action in audit trail
        identity = get_jwt_identity()
        db.audit_logs.insert_one(init_audit_log(
            user=identity.get('username'),
            action="Incident Changes",
            ip_address=request.remote_addr or '127.0.0.1',
            details=f"Simulated abnormal hours login from IP {source_ip} for username '{username}'"
        ))
        
        return jsonify({
            "message": "Abnormal hours security login simulation completed.",
            "source_ip": source_ip,
            "target": destination,
            "logs": logs_inserted
        }), 201
    except Exception as e:
        return jsonify({"message": "Simulation failed", "details": str(e)}), 500
