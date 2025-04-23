# ThreatDetector 🛡️

<div align="center">
  <img src="threat-detector-frontend\src\assets\logo.png" alt="ThreatDetector Logo" width="200"/>
  <br>
  <p><strong>Advanced malware detection platform powered by machine learning</strong></p>
  <a href="https://threatdetector.onrender.com">Live Demo</a> | 
  <a href="#features">Features</a> | 
  <a href="#tech-stack">Tech Stack</a> | 
  <a href="#installation">Installation</a> | 
  <a href="#usage">Usage</a>
</div>

## 📋 Overview

ThreatDetector is an advanced security platform designed to identify potential threats through sophisticated analysis of files and URLs. The platform uses machine learning models to detect malicious patterns in PE (Portable Executable) files and phishing URLs.

🔗 **Live Demo**: [https://threatdetector.onrender.com](https://threatdetector.onrender.com)

<div align="center">
  <img src="docs/images/dashboard.png" alt="ThreatDetector Dashboard" width="800"/>
</div>

## ✨ Features

- **PE File Analysis** - Detect malware in Windows executable files
- **URL Phishing Detection** - Identify potentially malicious websites
- **Detailed Threat Reports** - Get comprehensive information about detected threats
- **Modern, Responsive UI** - User-friendly interface that works on desktop and mobile
- **REST API** - Integrate with your existing security tools

<div align="center">
  <img src="docs/images/file-analysis.png" alt="File Analysis" width="400"/>
  <img src="docs/images/url-analysis.png" alt="URL Analysis" width="400"/>
</div>

## 🔧 Tech Stack

### Frontend

- **Vue.js 3** - Progressive JavaScript framework
- **Bootstrap 5** - Frontend CSS framework
- **Axios** - HTTP client for API requests
- **FontAwesome** - Icon library

### Backend

- **FastAPI** - Modern, high-performance web framework for Python
- **Uvicorn** - ASGI server
- **Scikit-learn** - Machine learning library for threat detection models
- **Pandas** - Data manipulation and analysis

### Machine Learning Models

- Custom PE file malware detection model
- URL phishing detection model

## 🚀 Installation

### Prerequisites

- Python 3.8+
- Node.js 14+
- npm or yarn

### Option 1: Using Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/reven7on/ThreatDetector.git
cd ThreatDetector

# Start the application with Docker Compose
docker-compose up --build
```

### Option 2: Manual Setup

#### Backend Setup

```bash
# Navigate to backend directory
cd threat-detector-backend

# Create and activate virtual environment
python -m venv venv
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the backend server
python main.py
```

#### Frontend Setup

```bash
# Navigate to frontend directory
cd threat-detector-frontend

# Install dependencies
npm install

# Run the development server
npm run serve
```

## 💻 Usage

1. **File Analysis**: Upload a PE file (Windows executable) to scan for malware
2. **URL Analysis**: Enter a URL to check if it's a potential phishing site
3. **View Results**: Get detailed analysis about potential threats

<div align="center">
  <img src="docs/images/results.png" alt="Analysis Results" width="800"/>
</div>

## 📚 API Documentation

The API documentation is available at the following endpoints:

- **Swagger UI**: `/docs`
- **ReDoc**: `/redoc`

### API Endpoints

- `GET /api/` - Welcome message
- `POST /api/file/check` - Check a file for malware
- `POST /api/url/check` - Check a URL for phishing

## 🌐 Deployment

### Deploying on Render

1. Fork this repository
2. Connect your GitHub account to [Render](https://render.com)
3. Create a new Web Service with the "Deploy from a Blueprint" option
4. Select your forked repository and the `render.yaml` blueprint
5. Deploy and access your application at the provided URL

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📬 Contact

For questions or feedback, please [open an issue](https://github.com/reven7on/ThreatDetector/issues) on GitHub.

---

<div align="center">
  Made with ❤️ by Makar Lyapich
</div>
