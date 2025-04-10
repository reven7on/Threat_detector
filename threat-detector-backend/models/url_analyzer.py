import pandas as pd
import numpy as np
import pickle
from urllib.parse import urlparse
import re
import math
import tldextract
import os

class URLAnalyzer:
    """
    Класс для анализа URL-адресов на предмет фишинга и вредоносных сайтов
    с использованием предобученной модели машинного обучения.
    """
    
    def __init__(self, model_path=None, model_info_path=None):
        """
        Инициализация анализатора URL
        
        Args:
            model_path (str): Путь к файлу модели LightGBM
            model_info_path (str): Путь к файлу с информацией о модели
        """
        # Определение путей к файлам модели
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        models_dir = os.path.join(base_dir, "models")
        
        # Списки возможных путей для поиска файлов моделей
        model_paths = []
        model_info_paths = []
        
        # Добавляем стандартные пути
        if model_path is None:
            model_paths = [
                os.path.join(models_dir, "phishing_detection_model.pkl"),  # Стандартный путь
                "/app/models/phishing_detection_model.pkl",  # Путь в Docker контейнере
                os.path.join("/app", "phishing_detection_model.pkl")  # Альтернативный путь
            ]
        else:
            model_paths.append(model_path)
        
        if model_info_path is None:
            model_info_paths = [
                os.path.join(models_dir, "phishing_model_info.pkl"),  # Стандартный путь
                "/app/models/phishing_model_info.pkl",  # Путь в Docker контейнере
                os.path.join("/app", "phishing_model_info.pkl")  # Альтернативный путь
            ]
        else:
            model_info_paths.append(model_info_path)
        
        # Загрузка модели, перебираем все возможные пути
        model_loaded = False
        model_info_loaded = False
        model_error = None
        model_info_error = None
        
        # Пытаемся загрузить файл модели
        for path in model_paths:
            try:
                print(f"Пытаемся загрузить модель из: {path}")
                with open(path, 'rb') as f:
                    self.model = pickle.load(f)
                    model_loaded = True
                    print(f"Модель успешно загружена из: {path}")
                    break
            except Exception as e:
                model_error = e
                print(f"Не удалось загрузить модель из {path}: {e}")
        
        # Пытаемся загрузить информацию о модели
        for path in model_info_paths:
            try:
                print(f"Пытаемся загрузить информацию о модели из: {path}")
                with open(path, 'rb') as f:
                    self.model_info = pickle.load(f)
                    model_info_loaded = True
                    print(f"Информация о модели успешно загружена из: {path}")
                    break
            except Exception as e:
                model_info_error = e
                print(f"Не удалось загрузить информацию о модели из {path}: {e}")
        
        # Проверяем, удалось ли загрузить все необходимые файлы
        if model_loaded and model_info_loaded:
            self.label_encoder = self.model_info['label_encoder']
            self.phishing_idx = self.model_info['phishing_idx']
            self.feature_names = self.model_info['feature_names']
            self.is_loaded = True
            print(f"Модель успешно загружена. Распознаёт классы: {self.label_encoder.classes_}")
        else:
            self.is_loaded = False
            if not model_loaded:
                print(f"Ошибка при загрузке модели: {model_error}")
            if not model_info_loaded:
                print(f"Ошибка при загрузке информации о модели: {model_info_error}")
    
    def extract_features(self, url):
        """
        Извлечение признаков из URL для анализа
        
        Args:
            url (str): URL для анализа
            
        Returns:
            DataFrame: Таблица с признаками
        """
        urls = pd.Series([url])
        features = pd.DataFrame()
        
        # 1. Длина URL и его компонентов
        features['url_length'] = urls.apply(len)
        
        # Парсинг URL для извлечения компонентов
        parsed_urls = urls.apply(lambda x: urlparse(x))
        extracted = urls.apply(lambda x: tldextract.extract(x))
        
        # 2. Домен и его компоненты
        features['domain_length'] = parsed_urls.apply(lambda x: len(x.netloc) if x.netloc else 0)
        features['path_length'] = parsed_urls.apply(lambda x: len(x.path) if x.path else 0)
        features['subdomain_length'] = extracted.apply(lambda x: len(x.subdomain) if x.subdomain else 0)
        features['tld_length'] = extracted.apply(lambda x: len(x.suffix) if x.suffix else 0)
        
        # 3. Количество определенных символов и компонентов
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
        
        # 4. Другие полезные счетчики
        features['digit_count'] = urls.apply(lambda x: sum(c.isdigit() for c in x))
        features['letter_count'] = urls.apply(lambda x: sum(c.isalpha() for c in x))
        features['digit_letter_ratio'] = features['digit_count'] / (features['letter_count'] + 1)  # +1 чтобы избежать деления на 0
        
        # 5. Количество параметров в запросе
        features['param_count'] = parsed_urls.apply(lambda x: len(x.query.split('&')) if x.query else 0)
        
        # 6. Энтропия URL (мера случайности символов)
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
                entropy -= probability * math.log2(probability)
            
            return entropy
        
        features['url_entropy'] = urls.apply(calculate_entropy)
        features['domain_entropy'] = parsed_urls.apply(lambda x: calculate_entropy(x.netloc) if x.netloc else 0)
        features['path_entropy'] = parsed_urls.apply(lambda x: calculate_entropy(x.path) if x.path else 0)
        
        # 7. Проверка на наличие IP-адреса вместо домена
        ip_pattern = re.compile(r'^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))')
        features['has_ip_address'] = parsed_urls.apply(lambda x: 1 if ip_pattern.match(x.netloc) else 0)
        
        # 8. Количество директорий в пути
        features['dir_count'] = parsed_urls.apply(lambda x: x.path.count('/') if x.path else 0)
        
        # 9. Содержит ли URL определенные подозрительные слова
        suspicious_words = ['login', 'signin', 'verify', 'banking', 'secure', 'account', 'password', 'pwd', 'security']
        for word in suspicious_words:
            features[f'contains_{word}'] = urls.apply(lambda x: 1 if word in x.lower() else 0)
        
        # 10. Статистика по доменным зонам
        features['is_com'] = extracted.apply(lambda x: 1 if x.suffix == 'com' else 0)
        features['is_org'] = extracted.apply(lambda x: 1 if x.suffix == 'org' else 0)
        features['is_net'] = extracted.apply(lambda x: 1 if x.suffix == 'net' else 0)
        features['is_info'] = extracted.apply(lambda x: 1 if x.suffix == 'info' else 0)
        features['is_biz'] = extracted.apply(lambda x: 1 if x.suffix == 'biz' else 0)
        features['is_ru'] = extracted.apply(lambda x: 1 if x.suffix == 'ru' else 0)
        
        # 11. Базовые признаки для URL фишинга и вредоносных сайтов
        features['uses_https'] = urls.apply(lambda x: 1 if x.startswith('https://') else 0)
        features['is_shortened'] = urls.apply(lambda x: 1 if re.match(r'bit\.ly|goo\.gl|t\.co|tinyurl\.com|tr\.im|is\.gd|cli\.gs|ow\.ly|bit\.do', urlparse(x).netloc) else 0)
        
        return features
    
    def analyze(self, url):
        """
        Анализ URL на предмет угрозы
        
        Args:
            url (str): URL для анализа
            
        Returns:
            dict: Результаты анализа
        """
        if not self.is_loaded:
            return {
                "error": "Model not loaded",
                "url": url,
                "message": "URL analyzer model is not properly loaded"
            }
        
        try:
            # Извлечение признаков
            features_df = self.extract_features(url)
            
            # Убедимся, что у нас есть все нужные признаки в правильном порядке
            missing_features = set(self.feature_names) - set(features_df.columns)
            if missing_features:
                for feature in missing_features:
                    features_df[feature] = 0  # Заполняем отсутствующие признаки нулями
            
            # Выбираем только необходимые признаки в нужном порядке
            features_df = features_df[self.feature_names]
            
            # Выполнение предсказания
            pred_label = self.model.predict(features_df)
            pred_prob = self.model.predict_proba(features_df)
            
            # Подготовка результата
            predicted_class = self.label_encoder.inverse_transform(pred_label)[0]
            phishing_prob = pred_prob[0][self.phishing_idx]
            is_malicious = predicted_class != 'benign'
            
            # Определяем сообщение в зависимости от класса угрозы
            if is_malicious:
                if predicted_class == 'phishing':
                    message = "Внимание! Этот URL может быть фишинговым сайтом."
                elif predicted_class == 'malware':
                    message = "Внимание! Этот URL может содержать вредоносное ПО."
                else:
                    message = f"Внимание! Обнаружена угроза: {predicted_class}"
            else:
                message = "URL кажется безопасным."
            
            # Формируем результат
            result = {
                "is_malicious": is_malicious,
                "threat_type": predicted_class,
                "confidence": float(pred_prob[0][pred_label[0]]),
                "phishing_probability": float(phishing_prob),
                "url": url,
                "message": message,
                "probabilities": {
                    class_name: float(pred_prob[0][i]) 
                    for i, class_name in enumerate(self.label_encoder.classes_)
                }
            }
            
            return result
            
        except Exception as e:
            import traceback
            return {
                "error": str(e),
                "url": url,
                "message": "An error occurred during URL analysis",
                "traceback": traceback.format_exc()
            }