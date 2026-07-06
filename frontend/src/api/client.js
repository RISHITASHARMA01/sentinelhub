import axios from "axios"

// Base URL is configurable so the same build works against a locally
// dockerized backend (localhost:8001) or wherever it ends up deployed in
// Phase 6 -- never hardcode it.
const baseURL = import.meta.env.VITE_API_URL || "http://localhost:8001"

export const api = axios.create({ baseURL })

export const getLogsSummary = () => api.get("/logs/stats/summary").then((r) => r.data)
export const getLogsTimeseries = () => api.get("/logs/stats/timeseries").then((r) => r.data)
export const getLogs = (params) => api.get("/logs/", { params }).then((r) => r.data)

export const getAlertsSummary = () => api.get("/alerts/stats/summary").then((r) => r.data)
export const getAlertsTimeseries = () => api.get("/alerts/stats/timeseries").then((r) => r.data)
export const getAlerts = (params) => api.get("/alerts/", { params }).then((r) => r.data)
export const getAlert = (id) => api.get(`/alerts/${id}`).then((r) => r.data)
export const updateAlertStatus = (id, status) =>
  api.patch(`/alerts/${id}`, { status }).then((r) => r.data)
export const enrichAlert = (id) => api.post(`/alerts/${id}/enrich`).then((r) => r.data)

export const runDetection = () => api.post("/detect/run").then((r) => r.data)
