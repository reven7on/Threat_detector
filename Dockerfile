# Этап сборки фронтенда
FROM node:16-alpine AS frontend-build

WORKDIR /app/frontend

# Копируем файлы зависимостей фронтенда
COPY threat-detector-frontend/package*.json ./

# Устанавливаем зависимости
RUN npm install

# Копируем исходный код фронтенда
COPY threat-detector-frontend/ ./

# Собираем фронтенд для production
RUN npm run build

# Этап подготовки бэкенда и финального образа
FROM python:3.9-slim

# Устанавливаем nginx
RUN apt-get update && apt-get install -y nginx && \
    rm -rf /var/lib/apt/lists/*

# Копируем сборку фронтенда из предыдущего этапа
COPY --from=frontend-build /app/frontend/dist /var/www/html

# Рабочая директория для бэкенда
WORKDIR /app

# Копируем файл зависимостей бэкенда и устанавливаем их
COPY threat-detector-backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь код бэкенда
COPY threat-detector-backend/ ./

# Копируем конфигурацию nginx
COPY nginx.conf /etc/nginx/sites-available/default

# Скрипт запуска сервисов
RUN echo '#!/bin/bash \n\
    nginx \n\
    cd /app \n\
    python main.py' > /start.sh && \
    chmod +x /start.sh

# Открываем порт
EXPOSE 80

# Запускаем сервисы
CMD ["bash", "/start.sh"] 