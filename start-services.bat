@echo off
echo Starting ThreatDetector services...

:: Start the backend
start cmd /k "cd threat-detector-backend && python -m venv venv && venv\Scripts\activate && python -m pip install --upgrade pip && pip cache purge && pip install -r requirements.txt && python main.py"

:: Start the frontend
start cmd /k "cd threat-detector-frontend && npm install && npm run serve"

echo Services are starting. Please wait...
echo - Backend will be available at http://localhost:8000
echo - Frontend will be available at http://localhost:8080
echo - API documentation will be available at http://localhost:8000/docs 