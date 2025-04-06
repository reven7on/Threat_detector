from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os
import json
from api import file_analysis, url_analysis

app = FastAPI(title="ThreatDetector API")

# Get CORS settings from environment or use defaults
cors_origins_str = os.getenv("BACKEND_CORS_ORIGINS", '["http://localhost:8080", "http://localhost", "http://localhost:80"]')
cors_origins = json.loads(cors_origins_str)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
@app.get("/")
async def root():
    return {"message": "Welcome to ThreatDetector API"}

# Include routers
app.include_router(file_analysis.router, prefix="/api/file", tags=["File Analysis"])
app.include_router(url_analysis.router, prefix="/api/url", tags=["URL Analysis"])

if __name__ == "__main__":
    # In Docker, we want to listen on all interfaces
    host = "0.0.0.0" if os.getenv("DOCKER_ENV") else "127.0.0.1"
    uvicorn.run("main:app", host=host, port=8000, reload=False) 