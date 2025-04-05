<template>
  <div class="home">
    <div class="header">
      <div class="logo">
        <i class="fas fa-shield-virus"></i>
        <h1>ThreatDetector</h1>
      </div>
      <p class="tagline">Advanced malware detection platform</p>
    </div>

    <div class="container py-4">
      <div class="row">
        <div class="col-md-6 mb-4">
          <div class="scanner-card">
            <div class="card-header">
              <i class="fas fa-file-code me-2"></i>
              <h3>PE File Analysis</h3>
            </div>
            <div class="card-body">
              <FileUpload />
            </div>
          </div>
        </div>

        <div class="col-md-6 mb-4">
          <div class="scanner-card">
            <div class="card-header">
              <i class="fas fa-globe me-2"></i>
              <h3>URL Analysis</h3>
            </div>
            <div class="card-body">
              <UrlCheck />
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import FileUpload from "@/components/FileUpload.vue";
import UrlCheck from "@/components/UrlCheck.vue";

export default {
  name: "HomePage",
  components: {
    FileUpload,
    UrlCheck,
  },
};
</script>

<style scoped>
.home {
  min-height: 100vh;
  background-color: #121212;
  color: #e6e6e6;
}

.header {
  padding: 3rem 0;
  text-align: center;
  background-color: #191927;
  margin-bottom: 2rem;
  border-bottom: 1px solid #9d4edd;
}

.logo {
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 1rem;
}

.logo i {
  font-size: 2.5rem;
  margin-right: 1rem;
  color: #c77dff;
  text-shadow: 0 0 10px #9d4edd;
}

.logo h1 {
  font-weight: 700;
  font-size: 2.5rem;
  background: linear-gradient(90deg, #9d4edd, #c77dff);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  margin: 0;
}

.tagline {
  font-size: 1.2rem;
  color: #c77dff;
  opacity: 0.8;
}

.scanner-card {
  background-color: #191927;
  border-radius: 12px;
  overflow: hidden;
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.3);
  height: 100%;
  border: 1px solid #2c2c44;
  transition: all 0.3s;
}

.scanner-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 8px 30px rgba(157, 78, 221, 0.2);
  border-color: #9d4edd;
}

.card-header {
  background-color: #1e1e2f;
  color: #e6e6e6;
  padding: 1rem;
  display: flex;
  align-items: center;
  border-bottom: 1px solid #9d4edd;
}

.card-header i {
  color: #c77dff;
  font-size: 1.5rem;
  margin-right: 0.5rem;
}

.card-header h3 {
  margin: 0;
  font-size: 1.5rem;
}

.card-body {
  padding: 1.5rem;
}

/* Responsive adjustments */
@media (max-width: 768px) {
  .logo h1 {
    font-size: 2rem;
  }

  .logo i {
    font-size: 2rem;
  }

  .tagline {
    font-size: 1rem;
  }
}
</style>
