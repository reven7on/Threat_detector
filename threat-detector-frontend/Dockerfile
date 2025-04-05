FROM node:16-alpine

WORKDIR /app

# Копируем package.json и package-lock.json
COPY package*.json ./

# Устанавливаем зависимости
RUN npm install

# Копируем исходный код
COPY . .

# Открываем порт 8080
EXPOSE 8080

# Запускаем приложение
CMD ["npm", "run", "serve"]