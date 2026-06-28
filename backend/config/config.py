import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# App Settings
PORT = int(os.environ.get('PORT', 5000))
NODE_ENV = os.environ.get('NODE_ENV', 'development')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'cyberguard_super_secret_key')

# MongoDB Settings
MONGODB_URI = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017')
DB_NAME = os.environ.get('DB_NAME', 'cyberguard_siem')

# Correlation Alert Engine Settings (Requirement 3: config.py)
BRUTE_FORCE_FAILED_ATTEMPTS = int(os.environ.get('BRUTE_FORCE_FAILED_ATTEMPTS', 5))
BRUTE_FORCE_WINDOW_SECONDS = int(os.environ.get('BRUTE_FORCE_WINDOW_SECONDS', 10))

PORT_SCAN_PORT_COUNT = int(os.environ.get('PORT_SCAN_PORT_COUNT', 10))
PORT_SCAN_WINDOW_SECONDS = int(os.environ.get('PORT_SCAN_WINDOW_SECONDS', 5))

SUSPICIOUS_LOGIN_START_HOUR = int(os.environ.get('SUSPICIOUS_LOGIN_START_HOUR', 2))  # 2 AM
SUSPICIOUS_LOGIN_END_HOUR = int(os.environ.get('SUSPICIOUS_LOGIN_END_HOUR', 5))      # 5 AM
SUSPICIOUS_USERNAMES = ['admin', 'root', 'administrator']

# Token Expiry Settings
JWT_ACCESS_TOKEN_EXPIRES_HOURS = int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES_HOURS', 24))
