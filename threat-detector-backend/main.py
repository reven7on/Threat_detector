from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from api import file_analysis, url_analysis

app = FastAPI(title="ThreatDetector API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # В продакшене следует ограничить
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
    uvicorn.run("main:app", host="0.0.0.0", port=8000) 