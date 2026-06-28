# CyberGuard SIEM Lite - Installation Guide

This document details the step-by-step instructions to configure and run the CyberGuard SIEM Lite platform on a local Windows environment.

---

## 🛠️ Option 1: Local Virtual Environment Setup (Recommended)

### Prerequisites
1. **Python 3.12**: Download and install from [python.org](https://www.python.org/downloads/). Ensure you check "Add Python to PATH" during installation.
2. **MongoDB Community Server** (Optional): Download and install locally from [mongodb.com](https://www.mongodb.com/try/download/community).
   * *Note: If MongoDB is not running, the application will automatically fall back to local JSON files in `backend/data/` seamlessly.*

### Step 1: Create Virtual Environment
Open PowerShell or command prompt inside the root project directory:
```powershell
# Create venv
python -m venv venv

# Activate venv
.\venv\Scripts\activate
```

### Step 2: Install Python Dependencies
```powershell
# Navigate to backend
cd backend

# Install dependencies
pip install -r requirements.txt
```

### Step 3: Run Database Seeder Script
Seed default analysts accounts, 500 historical logs, alerts, and incidents:
```powershell
python utils/seeder.py
```
*Note: If MongoDB connection fails, you will see a console warning and the data will be written to `backend/data/*.json` files automatically.*

### Step 4: Boot Flask Server
Start the Flask back-channel application:
```powershell
python app.py
```
The server will start on **`http://localhost:5000`**. 

---

## 🐳 Option 2: Docker Compose Orchestration Setup

If you have Docker Desktop installed, you can boot the entire ecosystem (Flask backend + local MongoDB container) in one command.

### Step 1: Boot Compose Service
Run from the root directory (where `docker-compose.yml` is located):
```bash
docker-compose up --build
```

This launches:
- `cyberguard_mongo` (database daemon on port `27017`)
- `cyberguard_app` (Flask web app on port `5000`)

### Step 2: Seed inside Container (Optional)
To execute the database seeder inside the running Docker container:
```bash
docker exec -it cyberguard_app python utils/seeder.py
```

---

## 🧭 Step 5: Access the Web Console

Open your browser and navigate to:
👉 **[http://localhost:5000](http://localhost:5000)**

Log in using the pre-seeded analysts accounts:
* **Administrator**: `admin` / `adminpassword`
* **Security Analyst**: `analyst1` / `analystpassword`
