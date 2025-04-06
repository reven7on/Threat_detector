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

# Устанавливаем nginx и другие полезные утилиты для отладки
RUN apt-get update && apt-get install -y nginx procps vim nano curl && \
    rm -rf /var/lib/apt/lists/*

# Копируем сборку фронтенда из предыдущего этапа
COPY --from=frontend-build /app/frontend/dist /var/www/html

# Создаем рабочую директорию для приложения
WORKDIR /app

# Копируем файл зависимостей бэкенда и устанавливаем их
COPY threat-detector-backend/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Копируем весь код бэкенда
COPY threat-detector-backend/ ./

# Копируем конфигурацию nginx
COPY nginx.conf /etc/nginx/sites-available/default

# Копируем скрипты
COPY start-services.sh /
COPY debug-render.sh /
RUN chmod +x /start-services.sh /debug-render.sh

# Переменная PORT может быть переопределена при запуске контейнера
ENV PORT=80

# Открываем порт
EXPOSE $PORT

# Использовать упрощенный подход к запуску для Render
CMD ["/bin/sh", "/start-services.sh"] 