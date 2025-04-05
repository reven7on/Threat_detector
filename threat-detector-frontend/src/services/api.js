import axios from "axios";

// Use localhost for development, can be changed for production
const API_URL = "http://localhost:8000/api";

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
