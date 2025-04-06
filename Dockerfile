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

WORKDIR /app

# Устанавливаем nginx для раздачи статики фронтенда
RUN apt-get update && apt-get install -y nginx && \
    rm -rf /var/lib/apt/lists/*

# Копируем сборку фронтенда из предыдущего этапа
COPY --from=frontend-build /app/frontend/dist /var/www/html

# Копируем файлы зависимостей бэкенда
COPY threat-detector-backend/requirements.txt .

# Устанавливаем зависимости бэкенда
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Копируем весь код бэкенда
COPY threat-detector-backend/ ./

# Копируем конфигурацию nginx
COPY nginx.conf /etc/nginx/sites-available/default

# Создаем запускающий скрипт
COPY start-services.sh /app/
RUN chmod +x /app/start-services.sh

# Открываем порт для приложения
EXPOSE 80

# Запускаем nginx и Python приложение
CMD ["/app/start-services.sh"] 