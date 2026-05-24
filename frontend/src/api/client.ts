import axios from 'axios'
import { useAuthStore } from '@/store/authStore'

export const api = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
})

// Attach JWT token to every request
api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Auto-logout on 401
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      useAuthStore.getState().logout()
      window.location.href = '/login'
    }
    return Promise.reject(err)
  },
)

// ── Auth ────────────────────────────────────────────────────────────────────
export const authApi = {
  login: (email: string, password: string) =>
    api.post('/auth/login', new URLSearchParams({ username: email, password }), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    }),
  register: (email: string, username: string, password: string) =>
    api.post('/auth/register', { email, username, password }),
  me: () => api.get('/auth/me'),
}

// ── Reviews ─────────────────────────────────────────────────────────────────
export const reviewsApi = {
  list: (params?: Record<string, unknown>) => api.get('/reviews', { params }),
  get: (id: string) => api.get(`/reviews/${id}`),
  getComments: (id: string) => api.get(`/reviews/${id}/comments`),
  updateComment: (id: string, patch: Record<string, unknown>) =>
    api.patch(`/review-comments/${id}`, patch),
  listPRs: (params?: Record<string, unknown>) => api.get('/pull-requests', { params }),
  getPR: (id: string) => api.get(`/pull-requests/${id}`),
  getLatestReview: (prId: string) => api.get(`/pull-requests/${prId}/latest-review`),
}

// ── Repositories ────────────────────────────────────────────────────────────
export const reposApi = {
  list: () => api.get('/repositories'),
  get: (id: string) => api.get(`/repositories/${id}`),
  create: (data: Record<string, unknown>) => api.post('/repositories', data),
  update: (id: string, patch: Record<string, unknown>) =>
    api.patch(`/repositories/${id}`, patch),
  delete: (id: string) => api.delete(`/repositories/${id}`),
  stats: (id: string) => api.get(`/repositories/${id}/stats`),
}

// ── Security ─────────────────────────────────────────────────────────────────
export const securityApi = {
  listVulns: (params?: Record<string, unknown>) =>
    api.get('/security/vulnerabilities', { params }),
  getVuln: (id: string) => api.get(`/security/vulnerabilities/${id}`),
  updateVuln: (id: string, patch: Record<string, unknown>) =>
    api.patch(`/security/vulnerabilities/${id}`, patch),
  summary: () => api.get('/security/summary'),
  owaspBreakdown: () => api.get('/security/owasp-breakdown'),
  fileHeatmap: () => api.get('/security/file-heatmap'),
  trends: () => api.get('/security/trends'),
}

// ── Quality ──────────────────────────────────────────────────────────────────
export const qualityApi = {
  metrics: () => api.get('/quality/metrics'),
  trends: () => api.get('/quality/trends'),
  files: () => api.get('/quality/files'),
  issues: () => api.get('/quality/issues'),
}

// ── Analytics ────────────────────────────────────────────────────────────────
export const analyticsApi = {
  dashboard: () => api.get('/analytics/dashboard'),
  recentActivity: (limit = 10) => api.get('/analytics/recent-activity', { params: { limit } }),
  reviewsPerDay: (days = 14) => api.get('/analytics/reviews-per-day', { params: { days } }),
}

// ── Model Status ─────────────────────────────────────────────────────────────
export const modelApi = {
  status: () => api.get('/model/status'),
}
