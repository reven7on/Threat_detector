from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os
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
@app.get("/api")
async def root():
    return {"message": "Welcome to ThreatDetector API"}

# Include routers - обратите внимание, мы изменили префикс без "api/"
app.include_router(file_analysis.router, prefix="/api/file", tags=["File Analysis"])
app.include_router(url_analysis.router, prefix="/api/url", tags=["URL Analysis"])

# Примечание: код для монтирования статических файлов будет добавлен в Dockerfile
# app.mount("/", StaticFiles(directory="static", html=True), name="static")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port) 