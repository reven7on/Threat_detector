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

# Копируем файл зависимостей бэкенда и устанавливаем их
COPY threat-detector-backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь код бэкенда
COPY threat-detector-backend/ .

# Копируем собранный фронтенд в static директорию FastAPI
COPY --from=frontend-build /app/frontend/dist /app/static

# Открываем порт для Render
ENV PORT=10000

# Запускаем FastAPI приложение
CMD uvicorn main:app --host 0.0.0.0 --port $PORT 