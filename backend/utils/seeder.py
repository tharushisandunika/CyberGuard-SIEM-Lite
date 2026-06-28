import datetime
import random
import os
import sys

# Add backend directory to system path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.db import get_db, get_db_mode
from models.database import init_user, init_log, init_alert, init_incident, init_audit_log
from services.geoip import lookup_geoip

def seed_database():
    db = get_db()
    db_mode = get_db_mode()
    print(f"[*] Seeding database in mode: {db_mode}")
    
    # 1. Clear existing collections
    print("[*] Wiping existing data collections...")
    db.users.delete_many({})
    db.logs.delete_many({})
    db.alerts.delete_many({})
    db.incidents.delete_many({})
    db.audit_logs.delete_many({})
    
    # 2. Seed Users (1 Admin User, 2 Analyst Users) (Requirement 5, seeder spec)
    print("[*] Seeding default identities...")
    admin_doc = init_user("admin", "admin@cyberguard.local", "adminpassword", "Admin")
    db.users.insert_one(admin_doc)
    
    analyst1_doc = init_user("analyst1", "analyst1@cyberguard.local", "analystpassword", "Security Analyst")
    db.users.insert_one(analyst1_doc)
    
    analyst2_doc = init_user("analyst2", "analyst2@cyberguard.local", "analystpassword", "Security Analyst")
    db.users.insert_one(analyst2_doc)
    
    print("[+] Seeding complete for Admin (adminpassword) and Analysts (analystpassword)")

    # 3. Seed 500+ Security Logs (Requirement 5)
    print("[*] Generating 520 staggered security events logs...")
    sources = ['Nginx Web Server', 'Active Directory DC', 'SSH Daemon', 'MySQL Database', 'Palo Alto Firewall', 'Linux System Logs']
    ips = [
        '192.168.1.15', '192.168.1.30', '10.0.4.155', '10.0.4.22', 
        '172.16.8.99', '198.51.100.12', '203.0.113.15', '185.220.101.5',
        '198.51.100.101', '203.0.113.50', '192.0.2.75'
    ]
    usernames = ['admin', 'analyst1', 'analyst2', 'jdoe', 'db_backup', 'web_agent', 'system_cron', 'root']
    severities = ['Informational', 'Low', 'Medium', 'High', 'Critical']
    event_types = ['DB_QUERY', 'FILE_ACCESS', 'FIREWALL_BLOCK', 'PROCESS_START', 'LOGIN_SUCCESS', 'LOGIN_FAILED', 'PORT_CONNECTION']
    statuses = ['success', 'failure']
    
    now = datetime.datetime.utcnow()
    logs_data = []
    
    for i in range(520):
        # Stagger logs uniformly over the last 7 days
        time_delta_seconds = random.randint(0, 7 * 24 * 3600)
        log_timestamp = (now - datetime.timedelta(seconds=time_delta_seconds)).isoformat()
        
        source = random.choice(sources)
        ip = random.choice(ips)
        user = random.choice(usernames)
        severity = random.choice(severities)
        etype = random.choice(event_types)
        status = random.choice(statuses)
        
        # Format message
        if etype == 'LOGIN_SUCCESS':
            msg = f"Successful login for user '{user}'"
            status = 'success'
        elif etype == 'LOGIN_FAILED':
            msg = f"Failed SSH password authentication for user '{user}'"
            status = 'failure'
            severity = 'Medium'
        elif etype == 'PORT_CONNECTION':
            port = random.choice([21, 22, 23, 80, 443, 3389, 8080])
            msg = f"Connection attempt on TCP port {port}"
            status = 'failure' if port in [21, 23, 3389] else 'success'
        elif etype == 'DB_QUERY':
            msg = f"SELECT * FROM customer_records LIMIT {random.randint(10, 100)}"
            status = 'success'
            severity = 'Informational'
        else:
            msg = f"System log event registered for source service '{source}'"
            
        country, city = lookup_geoip(ip)
        
        log_doc = init_log(
            source=source,
            event_type=etype,
            severity=severity,
            ip_address=ip,
            username=user if etype in ['LOGIN_SUCCESS', 'LOGIN_FAILED'] else None,
            message=msg,
            status=status,
            country=country,
            city=city,
            timestamp=log_timestamp
        )
        logs_data.append(log_doc)
        
    # Bulk insert
    for l in logs_data:
        db.logs.insert_one(l)
    print(f"[+] Successfully seeded {len(logs_data)} events logs.")

    # 4. Seed 50 Alerts (Requirement 5)
    print("[*] Generating 50 security correlation alerts...")
    alert_types = ['Brute Force Attack', 'Port Scan', 'Suspicious Login', 'Unauthorized File Modification', 'Malware Ingest Checked']
    alert_severities = ['Low', 'Medium', 'High', 'Critical']
    alert_statuses = ['Open', 'Investigating', 'Resolved', 'Closed']
    
    alerts_data = []
    for i in range(50):
        # Stagger alerts over last 5 days
        time_delta_seconds = random.randint(0, 5 * 24 * 3600)
        alert_timestamp = (now - datetime.timedelta(seconds=time_delta_seconds)).isoformat()
        
        atype = random.choice(alert_types)
        severity = random.choice(alert_severities)
        status = random.choice(alert_statuses)
        ip = random.choice(ips)
        
        desc = f"SIEM Alert triggered: {atype} events detected from source node IP: {ip}"
        
        alert_doc = init_alert(
            alert_type=atype,
            severity=severity,
            source_ip=ip,
            description=desc,
            status=status
        )
        # Override created_at with staggered timestamp
        alert_doc['created_at'] = alert_timestamp
        alerts_data.append(alert_doc)
        
    for a in alerts_data:
        db.alerts.insert_one(a)
    print(f"[+] Successfully seeded {len(alerts_data)} alerts.")

    # 5. Seed 20 Incidents (Requirement 5)
    print("[*] Generating 20 incidents...")
    incident_titles = [
        'Active SSH Dictionary Probe', 'Database Exfiltration Threat', 
        'Ransomware Executable Flagged', 'Off-Hours Root Console Access',
        'Multiple Firewall Port Scans', 'Analyst Password Rotate Required',
        'External VPN Session Ingestion', 'Abnormal CPU Threshold Spike',
        'System Daemon Crash Loop', 'Internal Subnet Sweep Detected'
    ]
    incident_severities = ['Low', 'Medium', 'High', 'Critical']
    incident_statuses = ['Open', 'Investigating', 'Resolved', 'Closed']
    analysts = ['analyst1', 'analyst2', 'admin']
    
    incidents_data = []
    for i in range(20):
        time_delta_seconds = random.randint(0, 5 * 24 * 3600)
        inc_timestamp = (now - datetime.timedelta(seconds=time_delta_seconds)).isoformat()
        
        title = f"{random.choice(incident_titles)} (#{1000 + i})"
        desc = f"Security analyst review required for {title.lower()}. Investigate correlated log flows immediately."
        severity = random.choice(incident_severities)
        status = random.choice(incident_statuses)
        assigned = random.choice(analysts)
        
        inc_doc = init_incident(
            title=title,
            description=desc,
            severity=severity,
            assigned_to=assigned,
            status=status
        )
        inc_doc['created_at'] = inc_timestamp
        inc_doc['updated_at'] = inc_timestamp
        incidents_data.append(inc_doc)
        
    for inc in incidents_data:
        db.incidents.insert_one(inc)
    print(f"[+] Successfully seeded {len(incidents_data)} incident workflows.")

    # 6. Seed Audit Logs
    print("[*] Generating compliance audit logs...")
    db.audit_logs.insert_one(init_audit_log(
        user="system",
        action="User Changes",
        ip_address="127.0.0.1",
        details="System database successfully initialized and seeded with mock datasets."
    ))
    db.audit_logs.insert_one(init_audit_log(
        user="admin",
        action="Login Attempts",
        ip_address="127.0.0.1",
        details="Successful administrative console log in from local loopback address."
    ))
    print("[+] Seeding transactions logging complete.")
    print("[+] CYBERGUARD SIEM DATABASE COMPLETED.")

if __name__ == '__main__':
    seed_database()
