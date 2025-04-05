#!/bin/bash

# Выводим сообщение о запуске
echo "Starting ThreatDetector services with Docker..."

# Проверяем, установлен ли Docker
if ! command -v docker &> /dev/null; then
    echo "Docker не установлен! Пожалуйста, установите Docker:"
    echo "Для Alpine Linux: apk add docker"
    echo "Или посетите https://docs.docker.com/engine/install/"
    exit 1
fi

# Проверяем, установлен ли Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "Docker Compose не установлен! Пожалуйста, установите Docker Compose:"
    echo "Для Alpine Linux: apk add docker-compose"
    echo "Или посетите https://docs.docker.com/compose/install/"
    exit 1
fi

# Запускаем контейнеры
echo "Запуск Docker контейнеров..."
docker-compose up --build

# Это сообщение будет показано только если docker-compose был остановлен
echo ""
echo "Сервисы ThreatDetector остановлены"