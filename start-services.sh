#!/bin/bash
set -e

# Запускаем Nginx в фоновом режиме
nginx -g "daemon off;" &

# Настраиваем API для работы с Nginx
export BACKEND_CORS_ORIGINS='["http://localhost", "http://localhost:80", "https://*.render.com"]'

# Запускаем FastAPI бэкенд
cd /app
exec python main.py 