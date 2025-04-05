#!/bin/bash
echo "Starting ThreatDetector services..."

# Start the backend
echo "Starting backend..."
gnome-terminal -- bash -c "cd threat-detector-backend && python3 -m venv venv && source venv/bin/activate && python -m pip install --upgrade pip && pip install -r requirements.txt && python main.py; exec bash" &

# Start the frontend
echo "Starting frontend..."
gnome-terminal -- bash -c "cd threat-detector-frontend && npm install && npm run serve; exec bash" &

echo "Services are starting. Please wait..."
echo "- Backend will be available at http://localhost:8000"
echo "- Frontend will be available at http://localhost:8080"
echo "- API documentation will be available at http://localhost:8000/docs" 