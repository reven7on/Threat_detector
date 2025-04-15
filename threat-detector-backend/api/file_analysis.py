from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from models.file_analyzer import FileAnalyzer
import tempfile
import os
import shutil
from typing import Optional
import asyncio

router = APIRouter()
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
CHUNK_SIZE = 1024 * 1024  # 1MB chunks
TIMEOUT = 30  # 30 seconds timeout

@router.post("/check")
async def check_file(file: UploadFile = File(...)):
    if not file:
        raise HTTPException(status_code=400, detail="No file provided")
    
    # Проверяем размер файла
    file_size = 0
    temp_file = None
    temp_path = None
    
    try:
        # Создаем временный файл
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.exe')
        temp_path = temp_file.name
        
        # Чтение всего файла и запись во временный файл
        content = await file.read()
        file_size = len(content)
        
        if file_size > MAX_FILE_SIZE:
            return JSONResponse(
                status_code=413, 
                content={"error": "File too large", "max_size": MAX_FILE_SIZE}
            )
        
        # Записываем содержимое во временный файл
        temp_file.write(content)
        temp_file.close()
        
        print(f"Файл {file.filename} загружен и сохранен как {temp_path}")
        
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
            
            print(f"Результат анализа: {result}")
            
            # Конвертируем numpy типы в обычные Python типы
            def convert_numpy_types(obj):
                import numpy as np
                if isinstance(obj, dict):
                    return {k: convert_numpy_types(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_numpy_types(i) for i in obj]
                elif isinstance(obj, np.integer):
                    return int(obj)
                elif isinstance(obj, np.floating):
                    return float(obj)
                elif isinstance(obj, np.ndarray):
                    return convert_numpy_types(obj.tolist())
                elif isinstance(obj, np.bool_):
                    return bool(obj)
                else:
                    return obj
            
            # Конвертируем результат для безопасной сериализации
            result = convert_numpy_types(result)
            
            return JSONResponse(content=result)
        except asyncio.TimeoutError:
            raise HTTPException(status_code=408, detail="Analysis timeout")
            
    except Exception as e:
        import traceback
        print(f"Ошибка при анализе файла: {str(e)}")
        print(traceback.format_exc())
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "detail": traceback.format_exc()}
        )
    finally:
        # Очищаем временный файл
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
                print(f"Временный файл {temp_path} удален")
            except Exception as e:
                print(f"Ошибка при удалении временного файла: {str(e)}") 