# CyberGuard SIEM Lite – Security Event Monitoring Dashboard

CyberGuard SIEM Lite is a lightweight Security Information and Event Management (SIEM) console designed for security analysts and admins. It correlates system logs, alerts on threats, manages incidents, compiles compliance reports, and integrates a hacking simulator to visualize attacks.

---

## 📂 Project Navigation Directory

All detailed documentations are located inside the `docs/` folder:

1. 📐 **[SIEM Core Specifications README](file:///c:/Users/tharu/OneDrive/Desktop/CyberGuard-SIEM-Lite/docs/README.md)**: Architectural diagrams, database collections maps, and Postman API setups.
2. 🛠️ **[Installation & Setup Guide](file:///c:/Users/tharu/OneDrive/Desktop/CyberGuard-SIEM-Lite/docs/Installation_Guide.md)**: Steps to launch the virtual environment locally or orchestrate container structures using Docker Compose.
3. ⚡ **[REST API Specifications Guide](file:///c:/Users/tharu/OneDrive/Desktop/CyberGuard-SIEM-Lite/docs/API_Documentation.md)**: Request body parameters and JSON payload examples for all endpoints.

---

## ⚡ Quick Launch Checklist

### Local Bootstrapping
```bash
# Navigate to backend
cd backend

# Install dependencies (virtual environment recommended)
pip install -r requirements.txt

# Seed the database (creates fallback files if MongoDB is down)
python utils/seeder.py

# Launch Flask Server
python app.py
```
👉 Access: **`http://localhost:5000`**

### Docker Compose Launch
```bash
# Run from root workspace
docker-compose up --build
```
👉 Access: **`http://localhost:5000`**

---

## 👤 Analyst Login Credentials

The database seeder inserts two default profiles on initial launch:

* **Administrator Profile**
  * **Username**: `admin`
  * **Password**: `adminpassword`
* **Analyst Profile**
  * **Username**: `analyst1`
  * **Password**: `analystpassword`
