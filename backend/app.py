import os
import sys
from flask import Flask, render_template, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO

# Import configuration
from config.config import PORT, JWT_SECRET_KEY, NODE_ENV
from config.db import get_db, get_db_mode

# Import Blueprints
from routes.auth import auth_bp
from routes.logs import logs_bp
from routes.alerts import alerts_bp
from routes.incidents import incidents_bp
from routes.audit import audit_bp
from routes.reports import reports_bp
from routes.simulator import simulator_bp

# Import Services
from services.socket_service import init_socketio
from services.background_simulator import start_background_simulator

# Create Flask App pointing to Frontend folder
app = Flask(
    __name__,
    template_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), '../frontend/templates')),
    static_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), '../frontend/static'))
)

# Enable CORS Protection
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# Enable JWT
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
app.config['JWT_IDENTITY_CLAIM'] = 'identity'
jwt = JWTManager(app)

# Custom JWT Error Handlers
@jwt.unauthorized_loader
def unauthorized_callback(callback):
    return jsonify({"message": "Authorization token missing or invalid"}), 401

@jwt.invalid_token_loader
def invalid_token_callback(callback):
    return jsonify({"message": "Authorization token is invalid"}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"message": "Authorization token has expired"}), 401

# Enable Flask-Limiter for Rate Limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["300 per minute"], # High limit for testing/simulations
    storage_uri="memory://"
)

# Initialize WebSockets (Flask-SocketIO)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
init_socketio(socketio)

# Register API Blueprints
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(logs_bp, url_prefix='/api/logs')
app.register_blueprint(alerts_bp, url_prefix='/api/alerts')
app.register_blueprint(incidents_bp, url_prefix='/api/incidents')
app.register_blueprint(audit_bp, url_prefix='/api/audit')
app.register_blueprint(reports_bp, url_prefix='/api/reports')
app.register_blueprint(simulator_bp, url_prefix='/api/simulator')

# Swagger Spec Endpoint (Requirement 4: API Documentation)
@app.route('/api/swagger.json')
def get_swagger_json():
    """Generates complete Swagger/OpenAPI 3.0 specification mapping."""
    return jsonify({
        "openapi": "3.0.3",
        "info": {
            "title": "CyberGuard SIEM Lite REST API Documentation",
            "description": "API mappings for security log collections, alert engines, incidents lifecycles, and threat simulator panels.",
            "version": "1.0.0"
        },
        "servers": [{"url": "/api"}],
        "paths": {
            "/auth/register": {
                "post": {
                    "summary": "Register new Analyst account",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["username", "email", "password"],
                                    "properties": {
                                        "username": {"type": "string", "example": "analyst3"},
                                        "email": {"type": "string", "example": "analyst3@cyberguard.local"},
                                        "password": {"type": "string", "example": "analystpassword"},
                                        "role": {"type": "string", "enum": ["Admin", "Security Analyst"], "example": "Security Analyst"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {"201": {"description": "Analyst registered successfully"}}
                }
            },
            "/auth/login": {
                "post": {
                    "summary": "Authenticate session, return JWT access token",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["username", "password"],
                                    "properties": {
                                        "username": {"type": "string", "example": "analyst1"},
                                        "password": {"type": "string", "example": "analystpassword"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "Login successful"}}
                }
            },
            "/logs": {
                "post": {
                    "summary": "Ingest new security log (Trigger Alert Engine)",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["source", "event_type", "ip_address", "message", "status"],
                                    "properties": {
                                        "source": {"type": "string", "example": "SSH Daemon"},
                                        "event_type": {"type": "string", "example": "LOGIN_FAILED"},
                                        "ip_address": {"type": "string", "example": "198.51.100.101"},
                                        "message": {"type": "string", "example": "Failed login attempt for user admin"},
                                        "status": {"type": "string", "enum": ["success", "failure"], "example": "failure"},
                                        "severity": {"type": "string", "example": "Medium"},
                                        "username": {"type": "string", "example": "admin"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {"201": {"description": "Log ingested successfully"}}
                },
                "get": {
                    "summary": "Getpaginated correlated logs list",
                    "parameters": [
                        {"name": "page", "in": "query", "schema": {"type": "integer", "default": 1}},
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}},
                        {"name": "severity", "in": "query", "schema": {"type": "string"}},
                        {"name": "event_type", "in": "query", "schema": {"type": "string"}},
                        {"name": "ip_address", "in": "query", "schema": {"type": "string"}},
                        {"name": "search", "in": "query", "schema": {"type": "string"}}
                    ],
                    "responses": {"200": {"description": "Correlated logs list"}}
                }
            },
            "/alerts": {
                "get": {
                    "summary": "Get all raised security alerts",
                    "responses": {"200": {"description": "Raised alerts list"}}
                }
            },
            "/incidents": {
                "post": {
                    "summary": "Create manual incident triage workflow",
                    "responses": {"201": {"description": "Incident created"}}
                },
                "get": {
                    "summary": "Get all security incidents list",
                    "responses": {"200": {"description": "Incident list"}}
                }
            },
            "/reports/stats": {
                "get": {
                    "summary": "Get dashboard metrics summaries",
                    "responses": {"200": {"description": "Dashboard statistics JSON"}}
                }
            },
            "/reports/export/csv/{collection_type}": {
                "get": {
                    "summary": "Export logs, alerts, or incidents to CSV file",
                    "parameters": [{"name": "collection_type", "in": "path", "required": True, "schema": {"type": "string", "enum": ["logs", "alerts", "incidents"]}}],
                    "responses": {"200": {"description": "CSV attachment stream"}}
                }
            },
            "/reports/export/pdf": {
                "get": {
                    "summary": "Export executive SIEM compliance stats to PDF report",
                    "responses": {"200": {"description": "PDF attachment stream"}}
                }
            },
            "/simulator/brute-force": {
                "post": {
                    "summary": "Simulate SSH dictionary brute force attack",
                    "responses": {"201": {"description": "Attack simulated"}}
                }
            },
            "/simulator/port-scan": {
                "post": {
                    "summary": "Simulate port connection sweeps",
                    "responses": {"201": {"description": "Scan simulated"}}
                }
            },
            "/simulator/suspicious-login": {
                "post": {
                    "summary": "Simulate abnormal login attempt",
                    "responses": {"201": {"description": "Intrusion event logged"}}
                }
            }
        }
    })

# Jinja2 serving HTML templates
@app.route('/login')
def render_login():
    return render_template('login.html')

@app.route('/')
def render_index():
    return render_template('index.html')

@app.route('/logs')
def render_logs():
    return render_template('logs.html')

@app.route('/alerts')
def render_alerts():
    return render_template('alerts.html')

@app.route('/incidents')
def render_incidents():
    return render_template('incidents.html')

@app.route('/audit')
def render_audit():
    return render_template('audit.html')

@app.route('/api/docs')
def render_swagger_docs():
    return render_template('docs.html')

# Health Check Endpoint
@app.route('/api/health')
def health():
    return jsonify({
        "status": "healthy",
        "database": get_db_mode()
    })

if __name__ == '__main__':
    # Initialize background generator thread for SIEM live telemetry (Requirement 1)
    start_background_simulator()
    
    print(f"[*] Starting CyberGuard SIEM Server on Port {PORT}...")
    # SocketIO wrapping run
    socketio.run(app, host='0.0.0.0', port=PORT, debug=(NODE_ENV == 'development'), allow_unsafe_werkzeug=True)
