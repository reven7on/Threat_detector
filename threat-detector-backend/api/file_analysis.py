from fastapi import APIRouter, UploadFile, HTTPException
from fastapi.responses import JSONResponse
from models.file_analyzer import FileAnalyzer
import tempfile
import os
from typing import Optional
import asyncio

router = APIRouter()
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
CHUNK_SIZE = 1024 * 1024  # 1MB chunks
TIMEOUT = 30  # 30 seconds timeout

@router.post("/check")
async def check_file(file: UploadFile):
    if not file:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Проверяем размер файла
    file_size = 0
    temp_file = None
    try:
        # Создаем временный файл
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_path = temp_file.name
        
        # Читаем файл по частям и проверяем размер
        while chunk := await file.read(CHUNK_SIZE):
            file_size += len(chunk)
            if file_size > MAX_FILE_SIZE:
                raise HTTPException(status_code=413, detail="File too large")
            temp_file.write(chunk)
        
        temp_file.close()
        
        # Проверяем, является ли файл PE файлом
        file_analyzer = FileAnalyzer()
        is_pe = await file_analyzer._check_if_pe(temp_path)
        
        if not is_pe:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "Invalid file format",
                    "message": "Only PE (Portable Executable) files are supported",
                    "is_pe_file": False
                }
            )
        
        # Запускаем анализ с таймаутом
        try:
            result = await asyncio.wait_for(
                file_analyzer.analyze_file(temp_path),
                timeout=TIMEOUT
            )
            return JSONResponse(content=result)
        except asyncio.TimeoutError:
            raise HTTPException(status_code=408, detail="Analysis timeout")
            
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e)}
        )
    finally:
        # Очищаем временный файл
        if temp_file and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except:
                pass 