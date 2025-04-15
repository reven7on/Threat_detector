import os
import asyncio
from typing import Dict, Any
from .pe_analyzer import PEAnalyzer

class FileAnalyzer:
    """
    Analyzer for different types of files.
    Currently supports PE (Portable Executable) files.
    """
    
    def __init__(self):
        self.pe_analyzer = PEAnalyzer()
    
    async def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Asynchronously analyze a file for malicious content.
        
        Args:
            file_path (str): Path to the file to analyze
            
        Returns:
            dict: Analysis results
        """
        # Проверяем существование файла
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        # Проверяем, является ли файл PE файлом
        is_pe = await self._check_if_pe(file_path)
        
        if is_pe:
            # Используем PEAnalyzer для анализа PE файлов
            result = self.pe_analyzer.analyze(file_path)
            if "error" in result:
                raise ValueError(result["error"])
            return result
        else:
            return {
                "error": "Unsupported file type",
                "message": "Only PE (Portable Executable) files are supported",
                "is_pe_file": False
            }
    
    async def _check_if_pe(self, file_path: str) -> bool:
        """
        Проверяет, является ли файл PE файлом.
        """
        try:
            with open(file_path, 'rb') as f:
                # Читаем первые 2 байта для проверки MZ сигнатуры
                header = f.read(2)
                return header == b'MZ'
        except Exception:
            return False 