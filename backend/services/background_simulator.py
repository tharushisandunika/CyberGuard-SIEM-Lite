import threading
import time
import random
import datetime
from config.db import get_db
from services.geoip import lookup_geoip
from models.database import init_log
from services.alert_engine import process_log_correlation
from services.socket_service import emit_log

# Global control flag
_generator_running = False

def generate_random_log_entry():
    """Generates realistic server/security event logs."""
    sources = ['Nginx Web Server', 'Active Directory DC', 'SSH Daemon', 'MySQL Database', 'Palo Alto Firewall', 'Linux System Logs']
    
    ips = [
        '192.168.1.15', '192.168.1.30', '10.0.4.155', '10.0.4.22', 
        '172.16.8.99', '198.51.100.12', '203.0.113.15', '185.220.101.5'
    ]
    
    users = ['admin', 'analyst', 'jdoe', 'db_backup', 'web_agent', 'system_cron', 'root']
    
    events = [
        # Normal Logs
        {
            "event_type": "DB_QUERY",
            "severity": "Informational",
            "message": "SELECT * FROM transactions WHERE amount > 1000",
            "status": "success",
            "source": "MySQL Database"
        },
        {
            "event_type": "FILE_ACCESS",
            "severity": "Low",
            "message": "User read file config.json",
            "status": "success",
            "source": "Nginx Web Server"
        },
        {
            "event_type": "FIREWALL_ALLOW",
            "severity": "Informational",
            "message": "Inbound connection allowed from external host",
            "status": "success",
            "source": "Palo Alto Firewall"
        },
        {
            "event_type": "PROCESS_START",
            "severity": "Low",
            "message": "Process cron.service started",
            "status": "success",
            "source": "Linux System Logs"
        },
        # Login Attempts (failed / success)
        {
            "event_type": "LOGIN_SUCCESS",
            "severity": "Low",
            "message": "Successful administrator login",
            "status": "success",
            "source": "Active Directory DC"
        },
        {
            "event_type": "LOGIN_FAILED",
            "severity": "Medium",
            "message": "Failed SSH password authentication for user",
            "status": "failure",
            "source": "SSH Daemon"
        },
        {
            "event_type": "PORT_CONNECTION",
            "severity": "Low",
            "message": "Connection attempt on TCP port 80",
            "status": "success",
            "source": "Palo Alto Firewall"
        }
    ]

    event = random.choice(events).copy()
    ip = random.choice(ips)
    user = random.choice(users)
    source = event['source']
    
    # Custom tweaks for specific messages
    if event['event_type'] == 'LOGIN_SUCCESS':
        event['message'] = f"Successful login for user '{user}'"
    elif event['event_type'] == 'LOGIN_FAILED':
        event['message'] = f"Failed login attempt for user '{user}' (Access denied)"
    elif event['event_type'] == 'FILE_ACCESS':
        event['message'] = f"User '{user}' accessed file source_code_v2.tar.gz"
        
    # Apply GeoIP Tracking (Requirement 2)
    country, city = lookup_geoip(ip)
    
    return init_log(
        source=source,
        event_type=event['event_type'],
        severity=event['severity'],
        ip_address=ip,
        username=user,
        message=event['message'],
        status=event['status'],
        country=country,
        city=city
    )

def _loop_generator():
    global _generator_running
    print("[*] Background SIEM Log Generator Thread Started.")
    
    # Give the app a moment to start
    time.sleep(2)
    
    db = get_db()
    while _generator_running:
        try:
            # Generate a random log
            log_doc = generate_random_log_entry()
            
            # Save to Database (MongoDB or fallback JSON)
            db.logs.insert_one(log_doc)
            
            # Correlate for threats (Brute force checks, scans, etc.)
            process_log_correlation(log_doc)
            
            # Broadcast to clients via SocketIO
            emit_log(log_doc)
            
        except Exception as e:
            print(f"[-] Error in background SIEM log simulator: {e}")
            
        # Delay between simulated events (4 seconds)
        time.sleep(4)

def start_background_simulator():
    """Starts the background telemetry thread if not already running."""
    global _generator_running
    if not _generator_running:
        _generator_running = True
        thread = threading.Thread(target=_loop_generator)
        thread.daemon = True
        thread.start()

def stop_background_simulator():
    """Stops the background simulator thread."""
    global _generator_running
    _generator_running = False
