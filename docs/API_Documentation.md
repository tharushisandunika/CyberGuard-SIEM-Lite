# CyberGuard SIEM Lite - API Documentation

This document describes the REST API endpoints exposed by the CyberGuard SIEM Lite backend, complete with sample headers, requests, and response bodies. All endpoints are prefixed with `/api`.

---

## 🔐 1. Authentication Module (`/api/auth`)

### Register Analyst Account
* **URL**: `/api/auth/register`
* **Method**: `POST`
* **Headers**: `Content-Type: application/json`
* **Request Body**:
  ```json
  {
    "username": "analyst3",
    "email": "analyst3@cyberguard.local",
    "password": "analystpassword",
    "role": "Security Analyst"
  }
  ```
* **Response Status**: `201 Created`
* **Response Body**:
  ```json
  {
    "_id": "d7bfb9d4-c9c0-449e-bde1-12c82a201c10",
    "username": "analyst3",
    "email": "analyst3@cyberguard.local",
    "role": "Security Analyst",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```

### Login Analyst Account
* **URL**: `/api/auth/login`
* **Method**: `POST`
* **Request Body**:
  ```json
  {
    "username": "analyst1",
    "password": "analystpassword"
  }
  ```
* **Response Status**: `200 OK`
* **Response Body**:
  ```json
  {
    "_id": "e3cb2a1d-a99f-4318-8422-9dc887019ce2",
    "username": "analyst1",
    "email": "analyst1@cyberguard.local",
    "role": "Security Analyst",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```

### Logout Analyst Account
* **URL**: `/api/auth/logout`
* **Method**: `POST`
* **Headers**: `Authorization: Bearer <token>`
* **Response Status**: `200 OK`
* **Response Body**:
  ```json
  {
    "message": "Logout successful"
  }
  ```

---

## 🔍 2. Log Management Module (`/api/logs`)

### Ingest Security Log (Trigger Alert Engine)
* **URL**: `/api/logs`
* **Method**: `POST`
* **Request Body**:
  ```json
  {
    "source": "Palo Alto Firewall",
    "event_type": "PORT_CONNECTION",
    "ip_address": "203.0.113.50",
    "message": "Connection attempt on TCP port 23",
    "status": "failure",
    "severity": "Low"
  }
  ```
* **Response Status**: `201 Created`
* **Response Body**:
  ```json
  {
    "_id": "f8a7c29e-219f-48d8-9dc9-1d92a101b023",
    "timestamp": "2026-06-22T10:50:00.123456",
    "source": "Palo Alto Firewall",
    "event_type": "PORT_CONNECTION",
    "ip_address": "203.0.113.50",
    "message": "Connection attempt on TCP port 23",
    "status": "failure",
    "severity": "Low",
    "country": "Japan",
    "city": "Tokyo"
  }
  ```

### Fetch Paginated Logs
* **URL**: `/api/logs`
* **Method**: `GET`
* **Headers**: `Authorization: Bearer <token>`
* **Query Parameters**:
  - `page`: Page index (default: `1`)
  - `limit`: Logs limit (default: `50`)
  - `search`: General text query search
  - `severity`: Filter by severity
  - `event_type`: Filter by type
  - `ip_address`: Filter by source IP
  - `startDate`/`endDate`: Range filter strings
* **Response Status**: `200 OK`
* **Response Body**:
  ```json
  {
    "logs": [
      {
        "_id": "f8a7c29e-...",
        "timestamp": "2026-06-22T10:50:00",
        "ip_address": "203.0.113.50",
        "source": "Palo Alto Firewall",
        "event_type": "PORT_CONNECTION",
        "severity": "Low",
        "message": "Connection attempt on TCP port 23",
        "status": "failure"
      }
    ],
    "page": 1,
    "pages": 12,
    "total": 180
  }
  ```

### Delete Security Log
* **URL**: `/api/logs/<id>`
* **Method**: `DELETE`
* **Headers**: `Authorization: Bearer <Admin-token>`
* **Response Status**: `200 OK`
* **Response Body**:
  ```json
  {
    "message": "Log deleted successfully"
  }
  ```

---

## 🚨 3. Alert Management Module (`/api/alerts`)

### Fetch Alerts List
* **URL**: `/api/alerts`
* **Method**: `GET`
* **Headers**: `Authorization: Bearer <token>`
* **Response Status**: `200 OK`

### Update Alert Triage
* **URL**: `/api/alerts/<id>`
* **Method**: `PUT`
* **Headers**: `Authorization: Bearer <token>`
* **Request Body**:
  ```json
  {
    "status": "Investigating",
    "assigned_to": "analyst1"
  }
  ```
* **Response Status**: `200 OK`

---

## 🛡️ 4. Incident Management Module (`/api/incidents`)

### Log Manual Incident
* **URL**: `/api/incidents`
* **Method**: `POST`
* **Request Body**:
  ```json
  {
    "title": "Incident Escalation: Database Leak",
    "description": "Correlating SQL queries showing excessive rows reads",
    "severity": "High",
    "assigned_to": "analyst1"
  }
  ```
* **Response Status**: `201 Created`

---

## 📊 5. Reporting Module (`/api/reports`)

### Get Posture Statistics Summary
* **URL**: `/api/reports/stats`
* **Method**: `GET`
* **Response Status**: `200 OK`

### Export CSV
* **URL**: `/api/reports/export/csv/<collection_type>`
* **Method**: `GET`
* **Path Parameters**: `logs`, `alerts`, `incidents`
* **Response**: CSV file stream download.

### Export PDF Compliance Report
* **URL**: `/api/reports/export/pdf`
* **Method**: `GET`
* **Response**: Binary PDF file stream download.
