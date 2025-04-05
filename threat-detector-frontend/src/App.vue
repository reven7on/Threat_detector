<template>
  <div id="app">
    <router-view />
    <footer class="footer">
      <div class="container text-center">
        <p>
          © {{ currentYear }} ThreatDetector | Advanced malware detection
          platform
        </p>
      </div>
    </footer>
  </div>
</template>

<script>
export default {
  name: "App",
  computed: {
    currentYear() {
      return new Date().getFullYear();
    },
  },
};
</script>

<style>
/* Global styles */
html,
body {
  margin: 0;
  padding: 0;
  font-family: "Poppins", "Segoe UI", Roboto, Arial, sans-serif;
  background-color: #121212;
}

#app {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  color: #e6e6e6;
}

.footer {
  margin-top: auto;
  padding: 1.5rem 0;
  background-color: #191927;
  border-top: 1px solid #9d4edd;
  color: #a0a0a0;
  font-size: 0.9rem;
}

/* Custom scrollbar */
::-webkit-scrollbar {
  width: 10px;
}

::-webkit-scrollbar-track {
  background: #191927;
}

::-webkit-scrollbar-thumb {
  background: #9d4edd;
  border-radius: 5px;
}

::-webkit-scrollbar-thumb:hover {
  background: #c77dff;
}

/* Override bootstrap */
.btn {
  border-radius: 5px;
}

.form-control {
  border-radius: 5px;
}

.progress {
  height: 12px;
  border-radius: 6px;
  background-color: #2c2c44;
}
</style>
