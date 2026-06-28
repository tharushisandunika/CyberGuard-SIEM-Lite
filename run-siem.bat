@echo off
echo =================================================================
echo             STARTING CYBERGUARD SIEM LITE (FLASK)
echo =================================================================
echo.
echo [*] Checking Python virtual environment (venv)...
if not exist "venv\" (
    echo [!] Virtual environment (venv) not found! Creating venv...
    python -m venv venv
)

echo [*] Activating Python virtual environment...
call venv\Scripts\activate

echo [*] Upgrading pip and installing python packages...
cd backend
call pip install --upgrade pip
call pip install -r requirements.txt
cd ..

echo [*] Seeding database telemetry records...
cd backend
python utils/seeder.py
cd ..

echo.
echo =================================================================
echo [+] Launching CyberGuard SIEM Server on Port 5000...
echo [+] Console: http://localhost:5000
echo [+] Docs:    http://localhost:5000/api/docs
echo =================================================================
echo.

cd backend
python app.py
cd ..

pause
