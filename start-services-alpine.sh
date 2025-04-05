#!/bin/sh
echo "Starting ThreatDetector services..."

# Start the backend in background
echo "Starting backend..."
(cd threat-detector-backend && python3 -m venv venv && . venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt && python main.py) &
BACKEND_PID=$!

# Start the frontend in background
echo "Starting frontend..."
(cd threat-detector-frontend && npm install && npm run serve) &
FRONTEND_PID=$!

echo "Services are starting. Please wait..."
echo "- Backend will be available at http://localhost:8000"
echo "- Frontend will be available at http://localhost:8080"
echo "- API documentation will be available at http://localhost:8000/docs"
echo
echo "Press Ctrl+C to stop all services"

# Wait for user to press Ctrl+C
trap "kill $BACKEND_PID $FRONTEND_PID; exit" INT
wait 