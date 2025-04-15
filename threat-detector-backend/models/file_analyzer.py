import os
import asyncio
import pefile
import hashlib
import math
import numpy as np
import pandas as pd
import pickle
from typing import Dict, Any

class FileAnalyzer:
    """
    Analyzer for different types of files.
    Currently supports PE (Portable Executable) files.
    """
    
    def __init__(self):
        # Путь к корневой директории проекта
        root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        # Возможные пути к моделям - проверяем различные варианты расположения
        possible_model_paths = [
            os.path.join(root_dir, "Models"),  # с большой буквы
            os.path.join(root_dir, "models"),  # с маленькой буквы
            os.path.join(os.getcwd(), "Models"),  # в текущем рабочем каталоге с большой буквы
            os.path.join(os.getcwd(), "models"),  # в текущем рабочем каталоге с маленькой буквы
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models"),  # в директории backend/models
        ]
        
        # Модели для поиска
        model_filename = 'pe_malware_detection_model.pkl'
        model_info_filename = 'pe_malware_model_info.pkl'
        
        # Инициализируем пути к моделям
        self.model_path = None
        self.model_info_path = None
        
        # Ищем модели в возможных путях
        for models_dir in possible_model_paths:
            potential_model_path = os.path.join(models_dir, model_filename)
            potential_model_info_path = os.path.join(models_dir, model_info_filename)
            
            if os.path.exists(potential_model_path) and os.path.exists(potential_model_info_path):
                self.model_path = potential_model_path
                self.model_info_path = potential_model_info_path
                print(f"Найдены модели в директории: {models_dir}")
                break
        
        # Если модели не найдены, используем пути по умолчанию
        if self.model_path is None:
            default_dir = os.path.join(root_dir, "Models")
            self.model_path = os.path.join(default_dir, model_filename)
            self.model_info_path = os.path.join(default_dir, model_info_filename)
            print(f"Модели не найдены. Используем пути по умолчанию: {default_dir}")
            print(f"Проверенные пути: {possible_model_paths}")
        
        # Загружаем модель
        self.model = None
        self.model_info = None
        self.load_model()

    def load_model(self):
        """
        Загружает модель для анализа PE файлов
        """
        try:
            print(f"Загрузка модели из: {self.model_path}")
            if not os.path.exists(self.model_path):
                print(f"ОШИБКА: Файл модели не найден: {self.model_path}")
                self.model = None
                return
                
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            print(f"Загрузка информации о модели из: {self.model_info_path}")
            if not os.path.exists(self.model_info_path):
                print(f"ОШИБКА: Файл информации о модели не найден: {self.model_info_path}")
                self.model = None
                self.model_info = None
                return
                
            with open(self.model_info_path, 'rb') as f:
                self.model_info = pickle.load(f)
            
            print(f"Модель успешно загружена. Информация о модели: {self.model_info.keys() if self.model_info else 'Нет информации'}")
        except Exception as e:
            import traceback
            print(f"Ошибка загрузки модели: {str(e)}")
            print(traceback.format_exc())
            self.model = None
            self.model_info = None
    
    async def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Анализирует файл и определяет, является ли он вредоносным.
        
        Args:
            file_path (str): Путь к файлу для анализа
            
        Returns:
            dict: Результаты анализа
        """
        # Проверяем существование файла
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        # Проверяем, является ли файл PE файлом
        is_pe = await self._check_if_pe(file_path)
        
        if is_pe:
            # Анализируем PE файл
            return self._analyze_pe_file(file_path)
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
    
    def _get_entropy(self, data):
        """
        Вычисляет энтропию данных
        """
        if len(data) == 0:
            return 0.0
        
        occurences = [0] * 256
        for x in data:
            occurences[x] += 1
        
        entropy = 0
        for x in occurences:
            if x:
                p_x = float(x) / len(data)
                entropy -= p_x * math.log(p_x, 2)
        
        return entropy
    
    def _extract_pe_features(self, exe_path: str) -> Dict[str, Any]:
        """
        Извлекает характеристики из PE файла
        """
        features = {}
        
        try:
            pe = pefile.PE(exe_path)
            
            # Основные заголовки
            features['Machine'] = pe.FILE_HEADER.Machine
            features['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
            features['Characteristics'] = pe.FILE_HEADER.Characteristics
            
            # Optional Header
            if hasattr(pe, 'OPTIONAL_HEADER'):
                features['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
                features['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
                features['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
                features['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
                features['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
                features['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                features['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
                
                if hasattr(pe.OPTIONAL_HEADER, 'BaseOfData'):
                    features['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
                else:
                    features['BaseOfData'] = 0
                    
                features['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
                features['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
                features['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
                features['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
                features['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
                features['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
                features['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
                features['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
                features['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
                features['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
                features['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
                features['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
                features['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
                features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
                features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
                features['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
                features['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
                features['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
                features['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
                features['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
            
            # Секции
            features['SectionsNb'] = len(pe.sections)
            
            section_entropies = []
            section_raw_sizes = []
            section_virtual_sizes = []
            
            for section in pe.sections:
                section_data = section.get_data()
                if len(section_data) > 0:
                    section_entropies.append(self._get_entropy(section_data))
                section_raw_sizes.append(section.SizeOfRawData)
                section_virtual_sizes.append(section.Misc_VirtualSize)
            
            if section_entropies:
                features['SectionsMeanEntropy'] = np.mean(section_entropies)
                features['SectionsMinEntropy'] = min(section_entropies)
                features['SectionsMaxEntropy'] = max(section_entropies)
            else:
                features['SectionsMeanEntropy'] = 0
                features['SectionsMinEntropy'] = 0
                features['SectionsMaxEntropy'] = 0
            
            if section_raw_sizes:
                features['SectionsMeanRawsize'] = np.mean(section_raw_sizes)
                features['SectionsMinRawsize'] = min(section_raw_sizes)
                features['SectionMaxRawsize'] = max(section_raw_sizes)
            else:
                features['SectionsMeanRawsize'] = 0
                features['SectionsMinRawsize'] = 0
                features['SectionMaxRawsize'] = 0
            
            if section_virtual_sizes:
                features['SectionsMeanVirtualsize'] = np.mean(section_virtual_sizes)
                features['SectionsMinVirtualsize'] = min(section_virtual_sizes)
                features['SectionMaxVirtualsize'] = max(section_virtual_sizes)
            else:
                features['SectionsMeanVirtualsize'] = 0
                features['SectionsMinVirtualsize'] = 0
                features['SectionMaxVirtualsize'] = 0
            
            # Импорты
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                features['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
                imports_nb = 0
                imports_nb_ordinal = 0
                
                for module in pe.DIRECTORY_ENTRY_IMPORT:
                    imports_nb += len(module.imports)
                    for imp in module.imports:
                        if imp.ordinal is not None and imp.name is None:
                            imports_nb_ordinal += 1
                
                features['ImportsNb'] = imports_nb
                features['ImportsNbOrdinal'] = imports_nb_ordinal
            else:
                features['ImportsNbDLL'] = 0
                features['ImportsNb'] = 0
                features['ImportsNbOrdinal'] = 0
            
            # Экспорты
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                features['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            else:
                features['ExportNb'] = 0
            
            # Ресурсы
            resources_nb = 0
            resources_entropies = []
            resources_sizes = []
            
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                def process_resource_directory(directory):
                    nonlocal resources_nb
                    
                    for entry in directory.entries:
                        if hasattr(entry, 'directory'):
                            process_resource_directory(entry.directory)
                        else:
                            resources_nb += 1
                            try:
                                data = pe.get_data(entry.data.struct.OffsetToData, entry.data.struct.Size)
                                if len(data) > 0:
                                    resources_entropies.append(self._get_entropy(data))
                                    resources_sizes.append(len(data))
                            except:
                                continue
                
                process_resource_directory(pe.DIRECTORY_ENTRY_RESOURCE)
            
            features['ResourcesNb'] = resources_nb
            
            if resources_entropies:
                features['ResourcesMeanEntropy'] = np.mean(resources_entropies)
                features['ResourcesMinEntropy'] = min(resources_entropies)
                features['ResourcesMaxEntropy'] = max(resources_entropies)
            else:
                features['ResourcesMeanEntropy'] = 0
                features['ResourcesMinEntropy'] = 0
                features['ResourcesMaxEntropy'] = 0
            
            if resources_sizes:
                features['ResourcesMeanSize'] = np.mean(resources_sizes)
                features['ResourcesMinSize'] = min(resources_sizes)
                features['ResourcesMaxSize'] = max(resources_sizes)
            else:
                features['ResourcesMeanSize'] = 0
                features['ResourcesMinSize'] = 0
                features['ResourcesMaxSize'] = 0
            
            # LoadConfigurationSize
            features['LoadConfigurationSize'] = 0
            if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                features['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
            
            # VersionInformationSize
            features['VersionInformationSize'] = 0
            if hasattr(pe, 'VS_VERSIONINFO'):
                features['VersionInformationSize'] = len(pe.VS_VERSIONINFO)
            
            return features
            
        except Exception as e:
            print(f"Ошибка при извлечении характеристик: {str(e)}")
            return {}
    
    def _analyze_pe_file(self, file_path: str) -> Dict[str, Any]:
        """
        Анализирует PE файл с использованием обученной модели
        """
        try:
            if not self.model or not self.model_info:
                # Если модель не загружена, используем заглушку
                print("ВНИМАНИЕ: Модель не загружена. Используем заглушку.")
                
                # Получаем основную информацию о файле
                file_size = os.path.getsize(file_path)
                file_name = os.path.basename(file_path)
                
                # Вычисляем MD5 хеш файла
                md5_hash = hashlib.md5()
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        md5_hash.update(chunk)
                file_md5 = md5_hash.hexdigest()
                
                # Возвращаем заглушку с базовой информацией
                return {
                    "file_path": file_path,
                    "file_name": file_name,
                    "file_size": file_size,
                    "md5": file_md5,
                    "is_legitimate": True,
                    "is_malicious": False,
                    "legitimate_probability": 0.75,
                    "malicious_probability": 0.25,
                    "threat_type": "unknown",
                    "prediction": "Не определено (модель не загружена)",
                    "confidence": 0.75,
                    "message": "Модель анализа не загружена. Результат ненадежен.",
                    "is_fallback": True
                }

            if not os.path.exists(file_path):
                return {"error": f"Файл не найден: {file_path}"}

            # Проверяем является ли файл PE файлом
            with open(file_path, 'rb') as f:
                header = f.read(2)
                if header != b'MZ':
                    return {"error": "Файл не является PE файлом (отсутствует MZ сигнатура)"}

            # Извлекаем характеристики
            features = self._extract_pe_features(file_path)
            if not features:
                return {"error": "Не удалось извлечь характеристики из файла"}

            # Создаем DataFrame для предсказания
            feature_names = self.model_info['feature_names']
            features_df = pd.DataFrame([features])

            # Проверяем, есть ли все нужные фичи
            for feature in feature_names:
                if feature not in features_df.columns:
                    features_df[feature] = 0

            # Выбираем только нужные колонки в нужном порядке
            features_df = features_df[feature_names]

            # Делаем предсказание
            prediction = self.model.predict(features_df)[0]
            probabilities = self.model.predict_proba(features_df)[0]

            # Индекс класса вредоносного ПО
            malicious_class_index = self.model_info.get('malicious_class_index', 0)

            # Интерпретируем результаты
            is_legitimate = prediction == (1 - malicious_class_index)
            legitimate_prob = probabilities[1 - malicious_class_index]
            malicious_prob = probabilities[malicious_class_index]

            # Вычисляем MD5 хеш файла
            md5_hash = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
            file_md5 = md5_hash.hexdigest()

            # Формируем результат в формате, совместимом с фронтендом
            result = {
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_size": os.path.getsize(file_path),
                "md5": file_md5,
                "is_legitimate": bool(is_legitimate),
                "is_malicious": not bool(is_legitimate),
                "legitimate_probability": float(legitimate_prob),
                "malicious_probability": float(malicious_prob),
                "threat_type": "malware" if not is_legitimate else "benign",
                "prediction": "Легитимный" if is_legitimate else "Вредоносный",
                "confidence": float(max(legitimate_prob, malicious_prob)),
                "message": "Этот файл может содержать вредоносный код." if not is_legitimate else "Файл безопасен."
            }

            return result

        except Exception as e:
            import traceback
            return {
                "error": f"Ошибка при анализе файла: {str(e)}",
                "traceback": traceback.format_exc()
            } 