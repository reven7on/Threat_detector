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

# Финальный этап - только бэкенд
FROM python:3.9-slim

WORKDIR /app

# Устанавливаем системные зависимости, необходимые для LightGBM и других библиотек
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Копируем файл зависимостей бэкенда и устанавливаем их
COPY threat-detector-backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Создаем директорию для моделей ПЕРЕД копированием моделей
RUN mkdir -p /app/models

# Копируем файлы моделей с хоста (из корневой папки Models) 
# в директорию /app/models внутри образа
COPY Models/*.pkl /app/models/

# Копируем весь остальной код бэкенда
COPY threat-detector-backend/ .

# Показываем содержимое директорий для отладки (убедимся, что модели скопировались)
RUN echo "Содержимое /app:" && ls -la /app
RUN echo "Содержимое /app/models:" && ls -la /app/models

# Копируем собранный фронтенд в static директорию FastAPI
COPY --from=frontend-build /app/frontend/dist /app/static

# Открываем порт для Render
ENV PORT=10000

# Запускаем FastAPI приложение
CMD uvicorn main:app --host 0.0.0.0 --port $PORT 