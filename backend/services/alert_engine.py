import datetime
import re
from config.db import get_db
from config.config import (
    BRUTE_FORCE_FAILED_ATTEMPTS, BRUTE_FORCE_WINDOW_SECONDS,
    PORT_SCAN_PORT_COUNT, PORT_SCAN_WINDOW_SECONDS,
    SUSPICIOUS_LOGIN_START_HOUR, SUSPICIOUS_LOGIN_END_HOUR,
    SUSPICIOUS_USERNAMES
)
from models.database import init_alert, init_audit_log
from services.socket_service import emit_alert

def parse_iso_date(date_str):
    if not date_str:
        return datetime.datetime.utcnow()
    # Replace 'Z' with UTC offset for isoformat parsing
    if date_str.endswith('Z'):
        date_str = date_str[:-1] + '+00:00'
    try:
        return datetime.datetime.fromisoformat(date_str)
    except Exception:
        return datetime.datetime.utcnow()

def process_log_correlation(log_doc):
    """
    Correlation engine checking rule definitions.
    Triggers alerts and broadcasts them over websocket.
    """
    db = get_db()
    if not db:
        return

    log_ip = log_doc.get('ip_address')
    log_time_str = log_doc.get('timestamp')
    log_time = parse_iso_date(log_time_str)

    # 1. Rule 1: Brute Force Attack Check
    if log_doc.get('status') == 'failure' and log_doc.get('event_type') == 'LOGIN_FAILED':
        ten_seconds_ago = (log_time - datetime.timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS)).isoformat()
        
        # Query failed logins from same IP within the window
        failed_logs = db.logs.find({
            "ip_address": log_ip,
            "event_type": "LOGIN_FAILED",
            "status": "failure",
            "timestamp": {"$gte": ten_seconds_ago}
        })
        
        if len(failed_logs) >= BRUTE_FORCE_FAILED_ATTEMPTS:
            # Check for existing open brute force alert from same IP in last 30 seconds
            thirty_seconds_ago = (log_time - datetime.timedelta(seconds=30)).isoformat()
            existing = db.alerts.find_one({
                "alert_type": "Brute Force Attack",
                "source_ip": log_ip,
                "status": {"$in": ["Open", "Investigating"]},
                "created_at": {"$gte": thirty_seconds_ago}
            })
            
            if not existing:
                desc = f"Detected {len(failed_logs)} failed login attempts from source IP {log_ip} within {BRUTE_FORCE_WINDOW_SECONDS} seconds."
                alert_data = init_alert(
                    alert_type="Brute Force Attack",
                    severity="High",
                    source_ip=log_ip,
                    description=desc
                )
                db.alerts.insert_one(alert_data)
                
                # Audit logging
                db.audit_logs.insert_one(init_audit_log(
                    user="Alert Engine",
                    action="Alert Changes",
                    ip_address="127.0.0.1",
                    details=f"Auto-generated Brute Force Attack alert for IP {log_ip}"
                ))
                
                # Emit WebSocket notification
                emit_alert(alert_data)

    # 2. Rule 2: Port Scan Check
    if log_doc.get('event_type') == 'PORT_CONNECTION':
        five_seconds_ago = (log_time - datetime.timedelta(seconds=PORT_SCAN_WINDOW_SECONDS)).isoformat()
        
        # Find port connection attempts from same IP in window
        connection_logs = db.logs.find({
            "ip_address": log_ip,
            "event_type": "PORT_CONNECTION",
            "timestamp": {"$gte": five_seconds_ago}
        })
        
        # Extract unique ports using regular expression
        unique_ports = set()
        for cl in connection_logs:
            msg = cl.get('message', '')
            # Parse port number from message like "Connection attempt on TCP port 80"
            match = re.search(r'port\s+(\d+)', msg, re.IGNORECASE)
            if match:
                unique_ports.add(match.group(1))
                
        if len(unique_ports) >= PORT_SCAN_PORT_COUNT:
            # Check for active alert within last 30s
            thirty_seconds_ago = (log_time - datetime.timedelta(seconds=30)).isoformat()
            existing = db.alerts.find_one({
                "alert_type": "Port Scan",
                "source_ip": log_ip,
                "status": {"$in": ["Open", "Investigating"]},
                "created_at": {"$gte": thirty_seconds_ago}
            })
            
            if not existing:
                desc = f"Source IP {log_ip} scanned {len(unique_ports)} unique TCP ports within {PORT_SCAN_WINDOW_SECONDS} seconds."
                alert_data = init_alert(
                    alert_type="Port Scan",
                    severity="High",
                    source_ip=log_ip,
                    description=desc
                )
                db.alerts.insert_one(alert_data)
                
                # Audit logging
                db.audit_logs.insert_one(init_audit_log(
                    user="Alert Engine",
                    action="Alert Changes",
                    ip_address="127.0.0.1",
                    details=f"Auto-generated Port Scan alert for IP {log_ip}"
                ))
                
                # Emit WebSocket
                emit_alert(alert_data)

    # 3. Rule 3: Suspicious Login Check
    if log_doc.get('event_type') == 'LOGIN_SUCCESS' and log_doc.get('status') == 'success':
        username = log_doc.get('username', '')
        # Check username condition
        contains_susp_username = any(name in username.lower() for name in SUSPICIOUS_USERNAMES)
        
        # Check abnormal hours condition (2 AM to 5 AM)
        hour = log_time.hour
        is_abnormal_hours = SUSPICIOUS_LOGIN_START_HOUR <= hour <= SUSPICIOUS_LOGIN_END_HOUR
        
        if contains_susp_username and is_abnormal_hours:
            thirty_seconds_ago = (log_time - datetime.timedelta(seconds=30)).isoformat()
            existing = db.alerts.find_one({
                "alert_type": "Suspicious Login",
                "source_ip": log_ip,
                "status": {"$in": ["Open", "Investigating"]},
                "created_at": {"$gte": thirty_seconds_ago}
            })
            
            if not existing:
                desc = f"Administrative login success for user '{username}' from IP {log_ip} at abnormal hour ({hour:02d}:{log_time.minute:02d} AM)."
                alert_data = init_alert(
                    alert_type="Suspicious Login",
                    severity="Critical",
                    source_ip=log_ip,
                    description=desc
                )
                db.alerts.insert_one(alert_data)
                
                # Audit logging
                db.audit_logs.insert_one(init_audit_log(
                    user="Alert Engine",
                    action="Alert Changes",
                    ip_address="127.0.0.1",
                    details=f"Auto-generated Critical Suspicious Login alert for IP {log_ip}"
                ))
                
                # Emit WebSocket
                emit_alert(alert_data)
