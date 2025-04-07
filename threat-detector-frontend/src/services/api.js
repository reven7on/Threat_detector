import axios from "axios";

// Определяем API URL в зависимости от окружения
// В production все запросы идут на тот же домен (через Nginx)
const isProd = process.env.NODE_ENV === "production";
const API_URL = isProd ? "/api" : "http://localhost:8000/api";

const api = axios.create({
  baseURL: API_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

export const fileService = {
  async checkFile(file) {
    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await api.post("/file/check", formData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });
      return response.data;
    } catch (error) {
      console.error("Error checking file:", error);
      throw error;
    }
  },
};

export const urlService = {
  async checkUrl(url) {
    try {
      const response = await api.post("/url/check", { url });
      return response.data;
    } catch (error) {
      console.error("Error checking URL:", error);
      throw error;
    }
  },
};
