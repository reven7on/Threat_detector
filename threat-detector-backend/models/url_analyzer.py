import pandas as pd
import numpy as np
import pickle
from urllib.parse import urlparse
import re
import math
import tldextract
import os
import traceback

class URLAnalyzer:
    """
    Класс для анализа URL-адресов на предмет фишинга
    с использованием бинарной классификационной модели (0 - безопасный, 1 - фишинг).
    """
    
    def __init__(self, model_path=None, model_info_path=None):
        """
        Инициализация анализатора URL
        
        Args:
            model_path (str): Путь к файлу модели
            model_info_path (str): Путь к файлу с информацией о модели
        """
        # Определение путей к файлам модели
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        models_dir = os.path.join(base_dir, "models")
        
        # Устанавливаем значения по умолчанию, если пути не указаны
        if model_path is None:
            model_path = os.path.join(models_dir, "binary_phishing_detection_model.pkl")
        
        if model_info_path is None:
            model_info_path = os.path.join(models_dir, "binary_phishing_model_info.pkl")
        
        # Инициализация свойств по умолчанию
        self.model = None
        self.model_info = None
        self.is_loaded = False
        self.class_names = ['0 (Безопасный)', '1 (Фишинг)']  # Имена по умолчанию для бинарной модели
        self.phishing_class_index = 1  # Индекс класса фишинга (по умолчанию 1)
        self.feature_names = []  # Имена признаков будут загружены из model_info
        
        # Попытка загрузки модели и информации
        try:
            print(f"Загрузка модели из: {model_path}")
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            print(f"Загрузка информации о модели из: {model_info_path}")
            with open(model_info_path, 'rb') as f:
                self.model_info = pickle.load(f)
            
            # Извлечение информации из model_info
            if 'classes' in self.model_info:
                self.class_names = self.model_info['classes']
                self.phishing_class_index = self.model_info.get('phishing_class_index', 1)
            
            # Загрузка имен признаков
            self.feature_names = self.model_info.get('feature_names', [])
            
            self.is_loaded = True
            print(f"Модель успешно загружена. Распознаёт классы: {self.class_names}")
            print(f"Загружено {len(self.feature_names)} признаков")
            
        except Exception as e:
            print(f"ОШИБКА при загрузке модели: {e}")
            print(traceback.format_exc())
            self.is_loaded = False
    
    def analyze(self, url):
        """
        Анализ URL на предмет угрозы
        
        Args:
            url (str): URL для анализа
            
        Returns:
            dict: Результаты анализа
        """
        # Проверяем загружена ли модель
        if not self.is_loaded or self.model is None:
            return {
                "error": "Model not loaded",
                "url": url,
                "is_malicious": False,
                "confidence": 0.0,
                "phishing_probability": 0.0,
                "message": "URL analyzer model is not properly loaded"
            }
        
        # Проверяем корректность URL
        if not isinstance(url, str) or not url:
            return {
                "error": "Invalid input URL",
                "url": url,
                "is_malicious": False,
                "confidence": 0.0,
                "phishing_probability": 0.0,
                "message": "Please provide a valid non-empty URL string."
            }
        
        try:
            # Нормализация URL перед извлечением признаков
            normalized_url = re.sub(r'^https?://(www\.)?', '', url).rstrip('/')
            
            # Извлечение признаков
            features_df = self.extract_features(pd.Series([normalized_url]))
            
            # Убедимся, что у нас есть все нужные признаки
            for feature in self.feature_names:
                if feature not in features_df.columns:
                    features_df[feature] = 0
            
            # Выбираем только необходимые признаки в нужном порядке
            features_df = features_df[self.feature_names]
            
            # Выполнение предсказания с явным преобразованием типов
            pred_label_idx = int(self.model.predict(features_df)[0])
            pred_prob = [float(p) for p in self.model.predict_proba(features_df)[0]]
            
            # Подготовка результата
            phishing_probability = float(pred_prob[self.phishing_class_index]) if self.phishing_class_index < len(pred_prob) else 0.0
            is_phishing = bool(pred_label_idx == self.phishing_class_index)
            
            # Сообщение в зависимости от класса угрозы
            if is_phishing:
                message = "Внимание! Этот URL может быть фишинговым сайтом."
            else:
                message = "URL кажется безопасным."
            
            # Формируем результат с гарантированно правильными типами данных
            result = {
                # Основные поля для фронтенда
                "is_malicious": bool(is_phishing),
                "confidence": float(pred_prob[pred_label_idx]),
                "phishing_probability": float(phishing_probability),
                "threat_type": "phishing" if is_phishing else "benign",
                "url": str(url),
                "message": str(message),
                
                # Дополнительные поля
                "normalized_url": str(normalized_url),
                "prediction_index": int(pred_label_idx),
                "probabilities": {
                    str(self.class_names[i]): float(prob) 
                    for i, prob in enumerate(pred_prob)
                }
            }
            
            # Гарантируем отсутствие NumPy типов в результате
            return self._convert_numpy_types(result)
            
        except Exception as e:
            print(f"Ошибка при анализе URL '{url}': {e}")
            print(traceback.format_exc())
            
            # Возвращаем ошибку в формате, который фронтенд может обработать
            return {
                "error": str(e),
                "url": url,
                "is_malicious": False,
                "confidence": 0.0,
                "phishing_probability": 0.0,
                "message": "Произошла ошибка при анализе URL."
            }
    
    def extract_features(self, urls):
        """
        Извлечение признаков из списка URL для задачи классификации.
        
        Args:
            urls (pd.Series): Серия URL для анализа
            
        Returns:
            pd.DataFrame: Датафрейм с признаками
        """
        features = pd.DataFrame()
        
        # Парсинг URL для извлечения компонентов
        parsed_urls = urls.apply(lambda x: urlparse(x))
        extracted = urls.apply(lambda x: tldextract.extract(x))
        
        # 1. use_of_ip - использование IP вместо домена
        ip_pattern = re.compile(r'^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))')
        features['has_ip_address'] = parsed_urls.apply(lambda x: 1 if ip_pattern.match(x.netloc) else 0)
        
        # 2. abnormal_url - ненормальный URL (содержит @ или // после протокола)
        features['abnormal_url'] = urls.apply(lambda x: 1 if '@' in x or re.search(r'https?://.*?//', x) else 0)
        
        # 3. url_length - длина URL
        features['url_length'] = urls.apply(len)
        
        # 4. domain_length - длина домена
        features['domain_length'] = parsed_urls.apply(lambda x: len(x.netloc) if x.netloc else 0)
        
        # 5. path_length - длина пути
        features['path_length'] = parsed_urls.apply(lambda x: len(x.path) if x.path else 0)
        
        # 6. subdomain_length - длина субдомена
        features['subdomain_length'] = extracted.apply(lambda x: len(x.subdomain) if x.subdomain else 0)
        
        # Получаем TLD (suffix)
        tlds = extracted.apply(lambda x: x.suffix.lower() if x.suffix else None)
        features['tld_length'] = tlds.apply(lambda x: len(x) if x else 0)
        
        # 7. Количество определенных символов и компонентов
        features['dot_count'] = urls.apply(lambda x: x.count('.'))
        features['hyphen_count'] = urls.apply(lambda x: x.count('-'))
        features['underscore_count'] = urls.apply(lambda x: x.count('_'))
        features['slash_count'] = urls.apply(lambda x: x.count('/'))
        features['question_mark_count'] = urls.apply(lambda x: x.count('?'))
        features['equal_sign_count'] = urls.apply(lambda x: x.count('='))
        features['at_symbol_count'] = urls.apply(lambda x: x.count('@'))
        features['ampersand_count'] = urls.apply(lambda x: x.count('&'))
        features['exclamation_count'] = urls.apply(lambda x: x.count('!'))
        features['space_count'] = urls.apply(lambda x: x.count(' '))
        features['tilde_count'] = urls.apply(lambda x: x.count('~'))
        features['comma_count'] = urls.apply(lambda x: x.count(','))
        features['plus_count'] = urls.apply(lambda x: x.count('+'))
        features['asterisk_count'] = urls.apply(lambda x: x.count('*'))
        features['hash_count'] = urls.apply(lambda x: x.count('#'))
        features['dollar_count'] = urls.apply(lambda x: x.count('$'))
        features['percent_count'] = urls.apply(lambda x: x.count('%'))
        
        # 8. Другие полезные счетчики
        features['digit_count'] = urls.apply(lambda x: sum(c.isdigit() for c in x))
        features['letter_count'] = urls.apply(lambda x: sum(c.isalpha() for c in x))
        features['digit_letter_ratio'] = features['digit_count'] / (features['letter_count'] + 1)  # +1 чтобы избежать деления на 0
        
        # 9. Количество параметров в запросе
        features['param_count'] = parsed_urls.apply(lambda x: len(x.query.split('&')) if x.query else 0)
        
        # 10. Энтропия URL (мера случайности символов)
        def calculate_entropy(text):
            if not text:
                return 0
            entropy = 0
            text_length = len(text)
            char_count = {}
            
            for char in text:
                if char in char_count:
                    char_count[char] += 1
                else:
                    char_count[char] = 1
            
            for count in char_count.values():
                probability = count / text_length
                if probability > 0:  # Избегаем log2(0)
                    entropy -= probability * math.log2(probability)
            
            return entropy
        
        features['url_entropy'] = urls.apply(calculate_entropy)
        features['domain_entropy'] = parsed_urls.apply(lambda x: calculate_entropy(x.netloc) if x.netloc else 0)
        features['path_entropy'] = parsed_urls.apply(lambda x: calculate_entropy(x.path) if x.path else 0)
        
        # 11. Количество директорий в пути
        features['dir_count'] = parsed_urls.apply(lambda x: x.path.count('/') if x.path else 0)
        
        # 12. Содержит ли URL определенные подозрительные слова
        suspicious_words = ['login', 'signin', 'verify', 'banking', 'secure', 'account', 'password', 'pwd', 'security', 'update', 'confirm', 'support']
        for word in suspicious_words:
            features[f'contains_{word}'] = urls.apply(lambda x: 1 if word in x.lower() else 0)
        
        # 13. Базовые признаки для URL фишинга
        features['uses_https'] = urls.apply(lambda x: 1 if x.startswith('https://') else 0)
        features['is_shortened'] = urls.apply(lambda x: 1 if re.match(r'bit\.ly|goo\.gl|t\.co|tinyurl\.com|tr\.im|is\.gd|cli\.gs|ow\.ly|bit\.do', urlparse(x).netloc) else 0)
        
        # 14. Признаки на основе TLD
        common_tlds = ['com', 'org', 'net', 'edu', 'gov', 'uk', 'ca', 'de', 'jp', 'fr', 'au', 'us', 'ru', 'ch', 'it', 'nl', 'se', 'no', 'es', 'mil']
        suspicious_tlds = ['xyz', 'top', 'club', 'site', 'online', 'info', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'link', 'click', 'buzz', 'stream', 'loan', 'download', 'review', 'vip', 'icu', 'support', 'security']

        for tld in common_tlds:
            features[f'is_tld_{tld}'] = tlds.apply(lambda x: 1 if x == tld else 0)

        features['is_suspicious_tld'] = tlds.apply(lambda x: 1 if x in suspicious_tlds else 0)
        features['is_uncommon_tld'] = tlds.apply(lambda x: 1 if x and x not in common_tlds else 0)
        features['is_cctld'] = tlds.apply(lambda x: 1 if x and len(x) == 2 and x.isalpha() else 0)
        
        return features
    
    def _convert_numpy_types(self, obj):
        """
        Рекурсивно преобразует numpy типы в стандартные типы Python
        для безопасной сериализации в JSON.
        
        Args:
            obj: Объект любого типа для конвертации
            
        Returns:
            Объект с преобразованными типами данных
        """
        if isinstance(obj, dict):
            return {k: self._convert_numpy_types(v) for k, v in obj.items()}
        elif isinstance(obj, list) or isinstance(obj, tuple):
            return [self._convert_numpy_types(x) for x in obj]
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, np.bool_):
            return bool(obj)
        else:
            return obj


# Пример использования (если запускать файл напрямую)
if __name__ == "__main__":
    analyzer = URLAnalyzer()
    
    test_urls = [
        "google.com",
        "https://www.google.com/",
        "facebook.com/login", 
        "paypa1-secure.com/login",
        "bit.ly/2Vxn3ad",
        "https://verify-your-account-apple.com/login",
        "youtube.com",
        "amazon.com",
        "banking-secure-login.com",
        "update-your-password.net"
    ]
    
    print("\nТестирование анализатора URL...")
    for url in test_urls:
        result = analyzer.analyze(url)
        print("\n" + "="*50)
        print(f"URL: {url}")
        print(f"Нормализованный URL: {result.get('normalized_url', 'N/A')}")
        print(f"Предсказание: {'Фишинг' if result.get('is_malicious') else 'Безопасный'}")
        print(f"Уверенность: {result.get('confidence', 0):.4f}")
        print(f"Вероятность фишинга: {result.get('phishing_probability', 0):.4f}")
        print(f"Сообщение: {result.get('message', 'N/A')}")