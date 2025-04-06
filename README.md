# ThreatDetector

Приложение для обнаружения потенциальных угроз на основе анализа файлов и URL.

## Локальная разработка

### С использованием Docker

1. Клонируйте репозиторий:

```
git clone https://github.com/ваш-юзернейм/ThreatDetector.git
cd ThreatDetector
```

2. Запустите приложение с помощью Docker Compose:

```
docker-compose up --build
```

3. Откройте браузер и перейдите по адресу: http://localhost

### Без Docker

#### Запуск бэкенда:

```
cd threat-detector-backend
python -m venv venv
source venv/bin/activate  # Для Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

#### Запуск фронтенда:

```
cd threat-detector-frontend
npm install
npm run serve
```

## Деплой на Render

1. Зарегистрируйтесь на [Render](https://render.com) и подключите свой GitHub репозиторий.

2. Создайте новый Web Service и выберите опцию "Deploy from a Blueprint".

3. Укажите путь к файлу `render.yaml` в вашем репозитории.

4. Нажмите "Apply" и дождитесь завершения деплоя.

5. Приложение будет доступно по предоставленному Render URL (обычно что-то вроде https://threatdetector.onrender.com).

## Структура проекта

- `threat-detector-frontend/` - Vue.js фронтенд
- `threat-detector-backend/` - FastAPI бэкенд
- `Dockerfile` - Единый Docker образ, содержащий фронтенд и бэкенд
- `docker-compose.yml` - Конфигурация для локальной разработки
- `render.yaml` - Конфигурация для деплоя на Render
- `nginx.conf` - Конфигурация Nginx для объединения фронтенда и бэкенда
- `start-services.sh` - Скрипт для запуска сервисов в Docker контейнере

## API Endpoints

- `GET /api/` - Приветственное сообщение API
- `POST /api/file/check` - Проверка файла на наличие вредоносного кода
- `POST /api/url/check` - Проверка URL на потенциальные угрозы

Интерактивная документация API доступна по адресам:

- Swagger UI: `/docs`
- ReDoc: `/redoc`
