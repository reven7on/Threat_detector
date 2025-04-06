#!/bin/bash
set -e

# Получаем порт из переменной окружения PORT или используем 80 по умолчанию
PORT=${PORT:-80}

# Вывод диагностической информации
echo "Starting services on port $PORT..."
echo "Current directory: $(pwd)"
echo "Files in current directory: $(ls -la)"

# Динамически создаем конфигурацию для Nginx, заменяя порт
echo "Configuring Nginx to listen on port $PORT..."
sed -i "s/listen 80;/listen $PORT;/" /etc/nginx/sites-available/default

# Проверяем конфигурацию Nginx
echo "Checking Nginx configuration..."
nginx -t

# Запускаем Nginx в фоновом режиме
echo "Starting Nginx..."
nginx -g "daemon off;" &
NGINX_PID=$!

# Настраиваем API для работы с Nginx
echo "Configuring backend environment..."
export BACKEND_CORS_ORIGINS='["http://localhost", "http://localhost:80", "https://*.render.com"]'
export DOCKER_ENV=true

# Делаем паузу, чтобы Nginx успел запуститься
sleep 2

# Проверяем, запустился ли Nginx
if kill -0 $NGINX_PID 2>/dev/null; then
    echo "Nginx is running with PID $NGINX_PID"
else
    echo "ERROR: Nginx failed to start"
    exit 1
fi

# Запускаем FastAPI бэкенд
echo "Starting FastAPI backend..."
cd /app
exec python main.py 