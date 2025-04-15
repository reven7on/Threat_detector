<template>
  <div class="file-upload">
    <div
      class="drop-area"
      :class="{ 'drag-over': isDragOver }"
      @dragover.prevent="isDragOver = true"
      @dragleave.prevent="isDragOver = false"
      @drop.prevent="handleFileDrop"
    >
      <div v-if="!selectedFile" class="upload-prompt">
        <i class="fas fa-cloud-upload-alt fa-3x"></i>
        <p class="mt-3">Drag and drop your PE file here, or</p>
        <button @click="$refs.fileInput.click()" class="btn glow-button">
          <i class="fas fa-file-upload me-2"></i>Select File
        </button>
        <p class="file-type-hint mt-2">
          <i class="fas fa-info-circle me-1"></i>
          Supported file types: Portable Executable (PE) files (.exe, .dll,
          .sys, .ocx, .scr)
        </p>
      </div>
      <div v-else class="selected-file">
        <p><i class="fas fa-file me-2"></i>{{ selectedFile.name }}</p>
        <div class="mt-3">
          <button @click="clearFile" class="btn btn-outline-secondary me-2">
            <i class="fas fa-times me-1"></i>Clear
          </button>
          <button
            @click="analyzeFile"
            class="btn glow-button"
            :disabled="isAnalyzing"
          >
            <i class="fas fa-search-plus me-2"></i
            >{{ isAnalyzing ? "Analyzing..." : "Analyze" }}
          </button>
        </div>
      </div>
    </div>

    <!-- Hidden input for file selection -->
    <input
      type="file"
      ref="fileInput"
      @change="handleFileSelect"
      style="display: none"
      accept=".exe,.dll,.sys,.ocx,.scr"
    />

    <!-- Error message for invalid file type -->
    <div v-if="fileTypeError" class="alert alert-danger mt-3">
      <i class="fas fa-exclamation-triangle me-2"></i>
      <strong>Invalid file type:</strong> {{ fileTypeError }}
    </div>

    <!-- Progress indicator (visible during analysis) -->
    <div v-if="isAnalyzing" class="analysis-progress">
      <div class="circular-progress">
        <div class="loader-ring">
          <div class="loader-ring-light"></div>
          <div class="loader-ring-track"></div>
        </div>
        <div class="progress-text">Analyzing...</div>
      </div>
    </div>

    <!-- Analysis results -->
    <div v-if="result" class="results mt-4">
      <!-- Warning alert for malicious files -->
      <div v-if="result.is_malicious" class="alert alert-danger mb-4">
        <div class="d-flex align-items-center">
          <i class="fas fa-exclamation-triangle fa-2x me-3"></i>
          <div>
            <h4 class="alert-heading mb-2">
              WARNING: Malicious File Detected!
            </h4>
            <p class="mb-0">
              This file has been identified as potentially malicious. It may
              contain viruses, trojans, or other harmful code. We recommend not
              using this file and deleting it immediately.
            </p>
          </div>
        </div>
      </div>

      <div class="report-card" :class="resultClass">
        <div class="report-header">
          <i :class="resultIcon" class="me-2"></i>
          <h4>Analysis Report</h4>
        </div>

        <div class="report-body">
          <div class="report-section">
            <h5>File Information</h5>
            <div class="info-row">
              <span class="info-label">File Name:</span>
              <span class="info-value">{{ selectedFile.name }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">File Size:</span>
              <span class="info-value">{{
                formatFileSize(selectedFile.size)
              }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">File Type:</span>
              <span class="info-value">{{
                result.file_type ||
                (result.is_pe_file ? "PE Executable" : "Unknown")
              }}</span>
            </div>
          </div>

          <div class="report-section">
            <h5>Threat Analysis</h5>
            <div class="threat-indicator">
              <div class="threat-meter">
                <div
                  class="threat-level"
                  :style="{
                    width:
                      (result.threat_percentage || result.confidence * 100) +
                      '%',
                  }"
                ></div>
              </div>
              <div class="threat-value">
                {{
                  result.threat_percentage
                    ? result.threat_percentage.toFixed(1)
                    : (result.confidence * 100).toFixed(1)
                }}%
              </div>
            </div>
            <div class="info-row">
              <span class="info-label">Status:</span>
              <span class="info-value">{{
                result.status || result.message
              }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Malware:</span>
              <span
                class="info-value status"
                :class="result.is_malicious ? 'status-bad' : 'status-good'"
              >
                {{ result.is_malicious ? "Detected" : "Not Detected" }}
              </span>
            </div>
          </div>

          <div class="report-section" v-if="!result.error">
            <h5>Recommendations</h5>
            <p v-if="result.is_malicious" class="recommendation warning">
              <i class="fas fa-exclamation-triangle me-2"></i>
              This file appears to be malicious. We recommend deleting it
              immediately and scanning your system for other threats.
            </p>
            <p v-else class="recommendation safe">
              <i class="fas fa-check-circle me-2"></i>
              File appears to be safe. However, always exercise caution when
              running executable files from unknown sources.
            </p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, computed, onUnmounted } from "vue";
import { useStore } from "vuex";
import { fileService } from "../services/api";

export default {
  name: "FileUpload",
  setup() {
    const store = useStore();

    const selectedFile = ref(null);
    const isDragOver = ref(false);
    const isAnalyzing = ref(false);
    const result = ref(null);
    const error = ref(null);
    const fileTypeError = ref(null);
    const progressValue = ref(0);
    const progressInterval = ref(null);

    const resultClass = computed(() => {
      if (!result.value) return "";
      if (result.value.error) return "alert-warning";
      if (result.value.is_malicious) return "alert-danger";
      return "alert-success";
    });

    const resultIcon = computed(() => {
      if (!result.value) return "";
      if (result.value.error) return "fas fa-exclamation-triangle";
      if (result.value.is_malicious) return "fas fa-virus";
      return "fas fa-shield-alt";
    });

    const startProgressBar = () => {
      progressValue.value = 0;
      progressInterval.value = setInterval(() => {
        if (progressValue.value < 90) {
          progressValue.value += Math.floor(Math.random() * 10) + 1;
        }
      }, 200);
    };

    const stopProgressBar = () => {
      if (progressInterval.value) {
        clearInterval(progressInterval.value);
        progressInterval.value = null;
      }
      progressValue.value = 100;
    };

    const isPEFile = (file) => {
      // Проверяем расширение файла
      const validExtensions = [".exe", ".dll", ".sys", ".ocx", ".scr"];
      const fileName = file.name.toLowerCase();
      return validExtensions.some((ext) => fileName.endsWith(ext));
    };

    const handleFileSelect = (event) => {
      const file = event.target.files[0];
      fileTypeError.value = null;

      if (file && !isPEFile(file)) {
        fileTypeError.value =
          "Only PE files (.exe, .dll, .sys, .ocx, .scr) are supported";
        selectedFile.value = null;
        return;
      }

      selectedFile.value = file;
      result.value = null;
    };

    const handleFileDrop = (event) => {
      isDragOver.value = false;
      const file = event.dataTransfer.files[0];
      fileTypeError.value = null;

      if (file && !isPEFile(file)) {
        fileTypeError.value =
          "Only PE files (.exe, .dll, .sys, .ocx, .scr) are supported";
        selectedFile.value = null;
        return;
      }

      selectedFile.value = file;
      result.value = null;
    };

    const clearFile = () => {
      selectedFile.value = null;
      result.value = null;
      fileTypeError.value = null;
      if (document.querySelector("input[type=file]")) {
        document.querySelector("input[type=file]").value = "";
      }
    };

    const analyzeFile = async () => {
      if (!selectedFile.value) return;

      if (!isPEFile(selectedFile.value)) {
        fileTypeError.value =
          "Only PE files (.exe, .dll, .sys, .ocx, .scr) are supported";
        return;
      }

      isAnalyzing.value = true;
      result.value = null;
      startProgressBar();

      try {
        const scanResult = await fileService.checkFile(selectedFile.value);
        console.log("Backend response:", scanResult); // Debug logging
        result.value = scanResult;

        // Если сервер сообщает, что файл не является PE файлом
        if (scanResult.error === "Invalid file format") {
          fileTypeError.value = scanResult.message;
        }

        // Save to history in store
        store.dispatch("addScanResult", {
          type: "file",
          name: selectedFile.value.name,
          result: scanResult,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        console.error("File analysis error:", err);
        error.value = err.message || "Error analyzing file";
        result.value = { error: error.value };
      } finally {
        isAnalyzing.value = false;
        stopProgressBar();
      }
    };

    const formatFileSize = (bytes) => {
      if (bytes === 0) return "0 Bytes";
      const k = 1024;
      const sizes = ["Bytes", "KB", "MB", "GB"];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    };

    onUnmounted(() => {
      if (progressInterval.value) {
        clearInterval(progressInterval.value);
      }
    });

    return {
      selectedFile,
      isDragOver,
      isAnalyzing,
      result,
      fileTypeError,
      progressValue,
      resultClass,
      resultIcon,
      handleFileSelect,
      handleFileDrop,
      clearFile,
      analyzeFile,
      formatFileSize,
    };
  },
};
</script>

<style scoped>
.file-upload {
  margin-bottom: 2rem;
}

.drop-area {
  border: 2px dashed #9d4edd;
  border-radius: 8px;
  padding: 40px;
  text-align: center;
  transition: all 0.3s;
  background-color: #1e1e2f;
}

.drag-over {
  background-color: #2c2c44;
  border-color: #c77dff;
}

.upload-prompt,
.selected-file {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}

.file-type-hint {
  color: #c77dff;
  font-size: 0.85rem;
  margin-top: 5px;
}

.glow-button {
  background-color: #9d4edd;
  border: none;
  box-shadow: 0 0 10px #c77dff;
  transition: all 0.3s;
  color: white;
}

.glow-button:hover:not(:disabled) {
  background-color: #c77dff;
  box-shadow: 0 0 15px #c77dff;
}

.glow-button:disabled {
  background-color: #9d4edd;
  opacity: 0.6;
  color: white;
  box-shadow: 0 0 5px rgba(199, 125, 255, 0.5);
}

/* Circular progress */
.analysis-progress {
  display: flex;
  justify-content: center;
  align-items: center;
  margin: 2rem 0;
}

.circular-progress {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
}

.loader-ring {
  position: relative;
  width: 100px;
  height: 100px;
}

.loader-ring-light {
  width: 100px;
  height: 100px;
  border-radius: 50%;
  box-shadow: 0 0 15px #c77dff;
  animation: pulse 1s ease-in-out infinite alternate;
}

.loader-ring-track {
  position: absolute;
  top: 0;
  left: 0;
  width: 100px;
  height: 100px;
  border-radius: 50%;
  border: 5px solid transparent;
  border-top: 5px solid #9d4edd;
  border-left: 5px solid #9d4edd;
  border-right: 5px solid transparent;
  border-bottom: 5px solid transparent;
  animation: rotate 1.5s ease-in-out infinite;
}

.progress-text {
  margin-top: 15px;
  font-weight: 500;
  color: #c77dff;
  text-shadow: 0 0 5px #9d4edd;
}

/* Enhanced report styles */
.report-card {
  background-color: #1e1e2f;
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
  border: 1px solid;
  transition: all 0.3s;
}

.report-card.alert-success {
  border-color: #4cc9f0;
  box-shadow: 0 10px 25px rgba(76, 201, 240, 0.1);
}

.report-card.alert-danger {
  border-color: #f72585;
  box-shadow: 0 10px 25px rgba(247, 37, 133, 0.1);
}

.report-card.alert-warning {
  border-color: #ffd166;
  box-shadow: 0 10px 25px rgba(255, 209, 102, 0.1);
}

.report-header {
  background-color: #191927;
  padding: 15px;
  display: flex;
  align-items: center;
  border-bottom: 1px solid;
}

.report-card.alert-success .report-header {
  border-color: #4cc9f0;
}

.report-card.alert-danger .report-header {
  border-color: #f72585;
}

.report-card.alert-warning .report-header {
  border-color: #ffd166;
}

.report-header i {
  font-size: 1.5rem;
}

.report-card.alert-success .report-header i {
  color: #4cc9f0;
}

.report-card.alert-danger .report-header i {
  color: #f72585;
}

.report-card.alert-warning .report-header i {
  color: #ffd166;
}

.report-header h4 {
  margin: 0;
  font-size: 1.3rem;
}

.report-body {
  padding: 20px;
}

.report-section {
  margin-bottom: 20px;
  padding-bottom: 20px;
  border-bottom: 1px solid #2c2c44;
}

.report-section:last-child {
  margin-bottom: 0;
  padding-bottom: 0;
  border-bottom: none;
}

.report-section h5 {
  margin-bottom: 15px;
  color: #c77dff;
  font-size: 1.1rem;
}

.info-row {
  display: flex;
  justify-content: space-between;
  margin-bottom: 10px;
}

.info-label {
  font-weight: 500;
  color: #a0a0a0;
}

.info-value {
  font-family: "Consolas", monospace;
}

.status {
  font-weight: 600;
  padding: 3px 8px;
  border-radius: 4px;
}

.status-good {
  background-color: rgba(76, 201, 240, 0.1);
  color: #4cc9f0;
}

.status-bad {
  background-color: rgba(247, 37, 133, 0.1);
  color: #f72585;
}

.threat-indicator {
  display: flex;
  align-items: center;
  margin-bottom: 15px;
}

.threat-meter {
  flex-grow: 1;
  height: 8px;
  background-color: #2c2c44;
  border-radius: 4px;
  overflow: hidden;
  margin-right: 10px;
}

.threat-level {
  height: 100%;
  background: linear-gradient(90deg, #4cc9f0, #c77dff, #f72585);
  border-radius: 4px;
}

.threat-value {
  font-weight: 600;
  min-width: 50px;
  text-align: right;
}

.recommendation {
  padding: 10px 15px;
  border-radius: 6px;
  font-size: 0.95rem;
}

.recommendation.warning {
  background-color: rgba(247, 37, 133, 0.1);
  color: #f72585;
}

.recommendation.safe {
  background-color: rgba(76, 201, 240, 0.1);
  color: #4cc9f0;
}

@keyframes rotate {
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
}

@keyframes pulse {
  0% {
    opacity: 0.4;
    transform: scale(0.95);
  }
  100% {
    opacity: 0.7;
    transform: scale(1.05);
  }
}

/* Warning alert styles */
.alert-danger {
  background-color: rgba(247, 37, 133, 0.1);
  border: 2px solid #f72585;
  color: #ffffff;
  animation: pulse-warning 2s infinite;
}

.alert-danger .alert-heading {
  color: #f72585;
  font-weight: 600;
}

.alert-danger i {
  color: #f72585;
}

@keyframes pulse-warning {
  0% {
    box-shadow: 0 0 0 0 rgba(247, 37, 133, 0.4);
  }
  70% {
    box-shadow: 0 0 0 10px rgba(247, 37, 133, 0);
  }
  100% {
    box-shadow: 0 0 0 0 rgba(247, 37, 133, 0);
  }
}
</style>
