from flask import Blueprint, request, jsonify, make_response
from flask_jwt_extended import jwt_required
from config.db import get_db
from middleware.security import analyst_required
import datetime
import csv
import io

# ReportLab Imports for PDF Export (Requirement: PDF Exporter)
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_stats():
    """
    Computes dashboard telemetry summary stats (Feature 1, 2).
    Includes total logs, alerts, active incidents, critical counts, top attacking IPs, and login geo distributions.
    """
    db = get_db()
    try:
        # Total counts
        total_logs = db.logs.count_documents({})
        total_alerts = db.alerts.count_documents({})
        active_incidents = db.incidents.count_documents({"status": {"$in": ["Open", "Investigating"]}})
        critical_alerts = db.alerts.count_documents({"severity": "Critical"})
        
        # Aggregate logs by severity for charts
        severity_counts = {
            "Informational": db.logs.count_documents({"severity": "Informational"}),
            "Low": db.logs.count_documents({"severity": "Low"}),
            "Medium": db.logs.count_documents({"severity": "Medium"}),
            "High": db.logs.count_documents({"severity": "High"}),
            "Critical": db.logs.count_documents({"severity": "Critical"}),
        }

        # Aggregate alerts by type
        alert_types = {}
        alerts = db.alerts.find({})
        for a in alerts:
            atype = a.get('alert_type', 'Unknown Alert')
            alert_types[atype] = alert_types.get(atype, 0) + 1
            
        # Top Attacking IPs aggregation
        ip_hits = {}
        # Fetch logs for IP hit aggregation
        # In Fallback JSON mode, we pull all; in MongoDB, limit search space or aggregate
        logs = db.logs.find({}, limit=2000)
        for l in logs:
            ip = l.get('ip_address')
            if ip and ip != '127.0.0.1' and ip != 'localhost' and ip != '::1':
                ip_hits[ip] = ip_hits.get(ip, 0) + 1
                
        top_ips = sorted([{"ip": k, "count": v} for k, v in ip_hits.items()], key=lambda x: x['count'], reverse=True)[:5]
        
        # GeoIP login locations (Grouping country and city)
        geo_hits = {}
        logs_geo = db.logs.find({"event_type": {"$in": ["LOGIN_SUCCESS", "LOGIN_FAILED"]}})
        for l in logs_geo:
            country = l.get('country', 'Internal Network')
            city = l.get('city', 'Local Subnet')
            if country != 'Internal Network':
                key = f"{city}, {country}"
                geo_hits[key] = geo_hits.get(key, 0) + 1
                
        geo_distributions = [{"location": k, "count": v} for k, v in geo_hits.items()]
        geo_distributions = sorted(geo_distributions, key=lambda x: x['count'], reverse=True)[:5]
        
        # Incidents by status
        incident_statuses = {
            "Open": db.incidents.count_documents({"status": "Open"}),
            "Investigating": db.incidents.count_documents({"status": "Investigating"}),
            "Resolved": db.incidents.count_documents({"status": "Resolved"}),
            "Closed": db.incidents.count_documents({"status": "Closed"})
        }

        # Formulate daily event line distribution (last 7 days counts)
        daily_events = []
        now = datetime.datetime.utcnow()
        for i in range(7):
            day = now - datetime.timedelta(days=i)
            day_str = day.strftime('%Y-%m-%d')
            # Check logs count for that day prefix
            count = db.logs.count_documents({"timestamp": {"$regex": f"^{day_str}"}})
            daily_events.append({"date": day.strftime('%b %d'), "count": count})
        daily_events.reverse()

        return jsonify({
            "summary": {
                "totalLogs": total_logs,
                "totalAlerts": total_alerts,
                "activeIncidents": active_incidents,
                "criticalAlerts": critical_alerts
            },
            "logsBySeverity": severity_counts,
            "alertsByType": alert_types,
            "incidentsByStatus": incident_statuses,
            "topAttackingIps": top_ips,
            "geoDistributions": geo_distributions,
            "dailyEvents": daily_events
        }), 200
    except Exception as e:
        return jsonify({"message": "Error calculating metrics", "details": str(e)}), 500

@reports_bp.route('/export/csv/<collection_type>', methods=['GET'])
@jwt_required()
def export_csv(collection_type):
    """CSV dynamic stream compiler exporter (Requirement 4)."""
    db = get_db()
    if collection_type not in ['logs', 'alerts', 'incidents']:
        return jsonify({"message": "Invalid CSV export target type"}), 400
        
    try:
        cursor = getattr(db, collection_type).find({}, limit=5000) # Cap at 5000 records
        
        si = io.StringIO()
        cw = csv.writer(si)
        
        if collection_type == 'logs':
            headers = ['_id', 'timestamp', 'source', 'event_type', 'severity', 'ip_address', 'username', 'message', 'status', 'country', 'city']
        elif collection_type == 'alerts':
            headers = ['_id', 'alert_type', 'severity', 'source_ip', 'description', 'status', 'created_at']
        else: # incidents
            headers = ['_id', 'title', 'description', 'severity', 'assigned_to', 'status', 'created_at', 'updated_at']
            
        cw.writerow(headers)
        for doc in cursor:
            cw.writerow([str(doc.get(h, '')) for h in headers])
            
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = f"attachment; filename=cyberguard_{collection_type}_export.csv"
        output.headers["Content-type"] = "text/csv"
        return output
    except Exception as e:
        return jsonify({"message": "Error generating CSV file", "details": str(e)}), 500

@reports_bp.route('/export/pdf', methods=['GET'])
@jwt_required()
def export_pdf():
    """PDF dynamic report compiler exporter (Requirement: PDF Exporter)."""
    db = get_db()
    try:
        total_logs = db.logs.count_documents({})
        total_alerts = db.alerts.count_documents({})
        active_incidents = db.incidents.count_documents({"status": {"$in": ["Open", "Investigating"]}})
        critical_alerts = db.alerts.count_documents({"severity": "Critical"})
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, 
            pagesize=letter, 
            rightMargin=40, 
            leftMargin=40, 
            topMargin=40, 
            bottomMargin=40
        )
        
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            textColor=colors.HexColor('#0f172a'),
            spaceAfter=8
        )
        
        subtitle_style = ParagraphStyle(
            'SubTitleStyle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor('#475569'),
            spaceAfter=25
        )
        
        section_style = ParagraphStyle(
            'SectionStyle',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=14,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=15,
            spaceAfter=10
        )
        
        body_style = styles['BodyText']
        
        story = []
        
        # Report Header
        story.append(Paragraph("CyberGuard SIEM Lite Compliance Report", title_style))
        story.append(Paragraph(f"Compiled At: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC | Scope: Corporate Network Logs Correlation", subtitle_style))
        story.append(Spacer(1, 10))
        
        # 1. Executive Summary Table
        story.append(Paragraph("1. EXECUTIVE SECURITY METRICS SUMMARY", section_style))
        data = [
            ['Security Posture Metric', 'Current System Count'],
            ['Total Network Events Correlated', str(total_logs)],
            ['Aggregated Correlation Alerts', str(total_alerts)],
            ['Active Incidents Under Review', str(active_incidents)],
            ['Critical Severity Threat Alarms', str(critical_alerts)]
        ]
        
        t = Table(data, colWidths=[320, 150])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (1, 0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0, 0), (1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f1f5f9')])
        ]))
        story.append(t)
        story.append(Spacer(1, 20))
        
        # 2. Alerts breakdown
        story.append(Paragraph("2. RECENT DETECTED ALERTS SUMMARY", section_style))
        alerts = db.alerts.find({}, limit=10, sort=[('created_at', -1)])
        
        alert_data = [['Alert Type', 'Severity', 'Source IP', 'Status']]
        for a in alerts:
            alert_data.append([
                a.get('alert_type', 'Unknown'),
                a.get('severity', 'Low'),
                a.get('source_ip', 'N/A'),
                a.get('status', 'Open')
            ])
            
        if len(alert_data) > 1:
            at = Table(alert_data, colWidths=[180, 80, 110, 100])
            at.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#475569')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ]))
            story.append(at)
        else:
            story.append(Paragraph("No security alerts detected in the database database.", body_style))
            
        story.append(Spacer(1, 25))
        story.append(Paragraph("Disclaimer: This document is an automatically generated posture compliance log compiled by CyberGuard SIEM. Do not distribute outside authorized SOC channels.", subtitle_style))
        
        doc.build(story)
        buffer.seek(0)
        
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=cyberguard_compliance_report.pdf'
        return response
    except Exception as e:
        return jsonify({"message": "Error generating PDF report file", "details": str(e)}), 500

@reports_bp.route('/daily', methods=['GET'])
@jwt_required()
def get_daily_report():
    return get_stats()

@reports_bp.route('/weekly', methods=['GET'])
@jwt_required()
def get_weekly_report():
    return get_stats()

@reports_bp.route('/monthly', methods=['GET'])
@jwt_required()
def get_monthly_report():
    return get_stats()
