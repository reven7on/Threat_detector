<template>
  <div class="url-check">
    <div class="url-input-container">
      <label for="urlInput" class="form-label">Enter URL to analyze:</label>
      <div class="input-group">
        <span class="input-group-text bg-dark"
          ><i class="fas fa-link"></i
        ></span>
        <input
          type="text"
          class="form-control bg-dark text-light"
          id="urlInput"
          v-model="url"
          placeholder="https://example.com"
          :disabled="isAnalyzing"
        />
        <button
          class="btn glow-button"
          @click="checkUrl"
          :disabled="!isValidUrl || isAnalyzing"
        >
          <i class="fas fa-search me-1"></i>
          {{ isAnalyzing ? "Analyzing..." : "Analyze" }}
        </button>
      </div>
      <small v-if="url && !isValidUrl" class="text-danger">
        <i class="fas fa-exclamation-circle me-1"></i>Please enter a valid URL
        (include http:// or https://)
      </small>
    </div>

    <!-- Progress indicator (visible during analysis) -->
    <div v-if="isAnalyzing" class="analysis-progress">
      <div class="circular-progress">
        <div class="loader-ring">
          <div class="loader-ring-light"></div>
          <div class="loader-ring-track"></div>
        </div>
        <div class="progress-text">Analyzing URL...</div>
      </div>
    </div>

    <!-- Analysis results -->
    <div v-if="result" class="results mt-4">
      <div class="report-card" :class="resultClass">
        <div class="report-header">
          <i :class="resultIcon" class="me-2"></i>
          <h4>URL Analysis Report</h4>
        </div>

        <div class="report-body">
          <div class="report-section">
            <h5>URL Information</h5>
            <div class="info-row">
              <span class="info-label">URL:</span>
              <span class="info-value url-value">{{ url }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Domain:</span>
              <span class="info-value">{{ extractDomain(url) }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Protocol:</span>
              <span class="info-value">{{ extractProtocol(url) }}</span>
            </div>
          </div>

          <div class="report-section">
            <h5>Threat Analysis</h5>
            <div class="threat-indicator">
              <div class="threat-meter">
                <div
                  class="threat-level"
                  :style="{ width: result.phishing_probability * 100 + '%' }"
                ></div>
              </div>
              <div class="threat-value">
                {{ (result.phishing_probability * 100).toFixed(1) }}%
              </div>
            </div>
            <div class="info-row">
              <span class="info-label">Status:</span>
              <span class="info-value">{{ result.message }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Malicious:</span>
              <span
                class="info-value status"
                :class="result.is_malicious ? 'status-bad' : 'status-good'"
              >
                {{ result.is_malicious ? "Yes" : "No" }}
              </span>
            </div>
          </div>

          <div class="report-section" v-if="!result.error">
            <h5>Risk Assessment</h5>
            <div class="risk-items" v-if="result.is_malicious">
              <div class="risk-item">
                <i class="fas fa-virus"></i>
                <span>Potential malware distribution</span>
              </div>
              <div class="risk-item">
                <i class="fas fa-user-secret"></i>
                <span>Possible phishing attempt</span>
              </div>
              <div class="risk-item">
                <i class="fas fa-bug"></i>
                <span>May contain exploit code</span>
              </div>
            </div>
            <p v-else class="recommendation safe">
              <i class="fas fa-check-circle me-2"></i>
              No known threats detected. This URL appears to be safe to visit.
            </p>
          </div>

          <div class="report-section" v-if="!result.error">
            <h5>Recommendations</h5>
            <p v-if="result.is_malicious" class="recommendation warning">
              <i class="fas fa-exclamation-triangle me-2"></i>
              We recommend avoiding this URL as it may pose security risks to
              your system or personal information.
            </p>
            <p v-else class="recommendation safe">
              <i class="fas fa-shield-alt me-2"></i>
              The URL appears to be safe. However, always be cautious about
              sharing sensitive information online.
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
import { urlService } from "../services/api";

export default {
  name: "UrlCheck",
  setup() {
    const store = useStore();

    const url = ref("");
    const isAnalyzing = ref(false);
    const result = ref(null);
    const error = ref(null);
    const progressValue = ref(0);
    const progressInterval = ref(null);

    const isValidUrl = computed(() => {
      if (!url.value) return false;
      try {
        new URL(url.value);
        return true;
      } catch (e) {
        return false;
      }
    });

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
      }, 150);
    };

    const stopProgressBar = () => {
      if (progressInterval.value) {
        clearInterval(progressInterval.value);
        progressInterval.value = null;
      }
      progressValue.value = 100;
    };

    const checkUrl = async () => {
      if (!isValidUrl.value) return;

      isAnalyzing.value = true;
      result.value = null;
      startProgressBar();

      try {
        const scanResult = await urlService.checkUrl(url.value);
        result.value = scanResult;

        // Save to history in store
        store.dispatch("addScanResult", {
          type: "url",
          name: url.value,
          result: scanResult,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        error.value = err.message || "Error analyzing URL";
        result.value = { error: error.value };
      } finally {
        isAnalyzing.value = false;
        stopProgressBar();
      }
    };

    const extractDomain = (url) => {
      try {
        const urlObj = new URL(url);
        return urlObj.hostname;
      } catch (e) {
        return "Invalid URL";
      }
    };

    const extractProtocol = (url) => {
      try {
        const urlObj = new URL(url);
        return urlObj.protocol.replace(":", "");
      } catch (e) {
        return "Unknown";
      }
    };

    onUnmounted(() => {
      if (progressInterval.value) {
        clearInterval(progressInterval.value);
      }
    });

    return {
      url,
      isAnalyzing,
      isValidUrl,
      result,
      progressValue,
      resultClass,
      resultIcon,
      checkUrl,
      extractDomain,
      extractProtocol,
    };
  },
};
</script>

<style scoped>
.url-check {
  margin-bottom: 2rem;
}

.url-input-container {
  background-color: #1e1e2f;
  border-radius: 8px;
  padding: 20px;
  border: 1px solid #9d4edd;
}

.input-group-text {
  color: #c77dff;
  border-color: #9d4edd;
}

.form-control {
  border-color: #9d4edd;
}

.form-control:focus {
  border-color: #c77dff;
  box-shadow: 0 0 0 0.25rem rgba(157, 78, 221, 0.25);
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
  max-width: 60%;
  word-break: break-all;
  text-align: right;
}

.url-value {
  font-size: 0.9rem;
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

.risk-items {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.risk-item {
  display: flex;
  align-items: center;
  padding: 10px;
  background-color: rgba(247, 37, 133, 0.05);
  border-radius: 6px;
  border-left: 3px solid #f72585;
}

.risk-item i {
  color: #f72585;
  margin-right: 10px;
  font-size: 1.1rem;
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
</style>
