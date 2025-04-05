# ThreatDetector Backend API

This is the backend API for the ThreatDetector application, built with FastAPI.

## Setup

1. Create a virtual environment:

```bash
python -m venv venv
```

2. Activate the virtual environment:

   - On Windows:

   ```bash
   venv\Scripts\activate
   ```

   - On Unix/MacOS:

   ```bash
   source venv/bin/activate
   ```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Running the API

Start the API server with:

```bash
python main.py
```

The API will be available at http://localhost:8000

You can access the interactive API documentation at:

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## API Endpoints

- `GET /`: Welcome message
- `POST /api/file/check`: Check if a file is malicious
- `POST /api/url/check`: Check if a URL is malicious
