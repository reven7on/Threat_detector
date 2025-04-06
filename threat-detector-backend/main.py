from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
import uvicorn
import os
import asyncio
from api import file_analysis, url_analysis

# Создаем приложение FastAPI
app = FastAPI(title="ThreatDetector API")

# Настраиваем CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # В продакшене следует ограничить
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Добавляем middleware для таймаутов
@app.middleware("http")
async def timeout_middleware(request: Request, call_next):
    try:
        return await asyncio.wait_for(call_next(request), timeout=60.0)
    except asyncio.TimeoutError:
        return JSONResponse(
            status_code=408,
            content={"error": "Request timeout"}
        )

# API маршруты
@app.get("/api")
async def root():
    return {"message": "Welcome to ThreatDetector API"}

# Подключаем API роутеры
app.include_router(file_analysis.router, prefix="/api/file", tags=["File Analysis"])
app.include_router(url_analysis.router, prefix="/api/url", tags=["URL Analysis"])

# Монтируем статические файлы
# Это нужно делать только если файлы существуют
if os.path.exists("static"):
    app.mount("/", StaticFiles(directory="static", html=True), name="static")

# Запуск приложения
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port) 