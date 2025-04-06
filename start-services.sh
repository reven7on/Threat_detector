#!/bin/bash
set -e

# Получаем порт из переменной окружения PORT или используем 80 по умолчанию
PORT=${PORT:-80}

# Динамически создаем конфигурацию для Nginx, заменяя порт
sed -i "s/listen 80;/listen $PORT;/" /etc/nginx/sites-available/default

echo "Starting services on port $PORT..."

# Запускаем Nginx в фоновом режиме
nginx -g "daemon off;" &

# Настраиваем API для работы с Nginx
export BACKEND_CORS_ORIGINS='["http://localhost", "http://localhost:80", "https://*.render.com"]'
export DOCKER_ENV=true

# Запускаем FastAPI бэкенд
cd /app
exec python main.py 