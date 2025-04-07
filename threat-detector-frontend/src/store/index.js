import { createStore } from "vuex";

export default createStore({
  state: {
    scanHistory: [],
  },
  getters: {
    getScanHistory: (state) => state.scanHistory,
  },
  mutations: {
    ADD_SCAN_RESULT(state, result) {
      state.scanHistory.unshift(result);
    },
  },
  actions: {
    addScanResult({ commit }, result) {
      commit("ADD_SCAN_RESULT", result);
    },
  },
});
