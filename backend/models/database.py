import datetime
import bcrypt

# password hashing helper using bcrypt
def hash_password(password):
    salt = bcrypt.gensalt(10)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def check_password(password, password_hash):
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        return False

# Mongo Document Schema Initializers
def init_user(username, email, password, role='Security Analyst'):
    return {
        "username": username.strip(),
        "email": email.strip().lower(),
        "password_hash": hash_password(password),
        "role": role, # Admin or Security Analyst
        "created_at": datetime.datetime.utcnow().isoformat()
    }

def init_log(source, event_type, severity, ip_address, username, message, status, country=None, city=None, timestamp=None):
    return {
        "timestamp": timestamp or datetime.datetime.utcnow().isoformat(),
        "source": source.strip(),
        "event_type": event_type.strip(),
        "severity": severity.strip(), # Informational, Low, Medium, High, Critical
        "ip_address": ip_address.strip(),
        "username": username.strip() if username else None,
        "message": message.strip(),
        "status": status.strip(), # success or failure
        "country": country or "Internal Network",
        "city": city or "Internal Subnet"
    }

def init_alert(alert_type, severity, source_ip, description, status='Open'):
    return {
        "alert_type": alert_type.strip(),
        "severity": severity.strip(), # Informational, Low, Medium, High, Critical
        "source_ip": source_ip.strip(),
        "description": description.strip(),
        "status": status.strip(), # Open, Investigating, Resolved, Closed
        "created_at": datetime.datetime.utcnow().isoformat()
    }

def init_incident(title, description, severity, assigned_to=None, status='Open'):
    return {
        "title": title.strip(),
        "description": description.strip(),
        "severity": severity.strip(), # Informational, Low, Medium, High, Critical
        "assigned_to": assigned_to.strip() if assigned_to else None,
        "status": status.strip(), # Open, Investigating, Resolved, Closed
        "created_at": datetime.datetime.utcnow().isoformat(),
        "updated_at": datetime.datetime.utcnow().isoformat()
    }

def init_audit_log(user, action, ip_address, details):
    return {
        "user": user.strip() if user else "system",
        "action": action.strip(), # e.g. Login Attempts, User Changes, Alert Changes, Incident Changes
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "ip_address": ip_address.strip() if ip_address else "127.0.0.1",
        "details": details.strip()
    }
