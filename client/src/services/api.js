import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');

    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    return config;
  },
  (error) => Promise.reject(error),
);

api.interceptors.response.use(
  (response) => response,
  (error) => Promise.reject(error),
);

export const auth = {
  register: (data) =>
    api.post('/auth/register', data),

  login: (data) =>
    api.post('/auth/login', data),

  me: () =>
    api.get('/auth/me'),
};

export const scan = {
  url: (url) =>
    api.post('/scan/url', { url }),

  history: () =>
    api.get('/scan/history'),
};

export const email = {
  analyze: (rawHeaders) =>
    api.post('/email/analyze', {
      raw_headers: rawHeaders,
    }),
};

export const threats = {
  recent: () =>
    api.get('/threats/recent'),

  fetchFeeds: () =>
    api.post('/threats/fetch'),
};

export const community = {
  getReports: () =>
    api.get('/community/reports'),

  submitReport: (data) =>
    api.post('/community/report', data),

  vote: (id, type) =>
    api.post(
      `/community/report/${id}/vote`,
      { type },
    ),
};

export const reports = {
  generate: async (scanData) => {
    const response = await api.post(
      '/reports/generate',
      scanData,
      {
        responseType: 'blob',
        timeout: 60000,
      },
    );

    const blob = new Blob(
      [response.data],
      {
        type: 'application/pdf',
      },
    );

    const url =
      window.URL.createObjectURL(blob);

    const link =
      document.createElement('a');

    link.href = url;
    link.download =
      `cybershield_report_${Date.now()}.pdf`;

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    window.URL.revokeObjectURL(url);
  },
};

export const recon = {
  portScan: (domain) =>
    api.post(
      '/recon/port-scan',
      { domain },
      { timeout: 60000 },
    ),

  abuseCheck: (domain) =>
    api.post(
      '/recon/abuse-check',
      { domain },
      { timeout: 45000 },
    ),

  full: (domain) =>
    api.post(
      '/recon/full',
      { domain },
      { timeout: 90000 },
    ),
};

export const gophish = {
  getCampaigns: () =>
    api.get('/gophish/campaigns'),

  getCampaign: (id) =>
    api.get(`/gophish/campaigns/${id}`),

  getPages: () =>
    api.get('/gophish/pages'),

  getTemplates: () =>
    api.get('/gophish/templates'),

  analyzeUrl: (url) =>
    api.post(
      '/gophish/analyze-url',
      { url },
      { timeout: 60000 },
    ),
};

export const yaraScan = {
  scan: (url) =>
    api.post(
      '/yara/scan',
      { url },
      { timeout: 60000 },
    ),

  getRules: () =>
    api.get('/yara/rules'),
};

export const breach = {
  checkPassword: (password) =>
    api.post(
      '/breach/check-password',
      { password },
      { timeout: 45000 },
    ),

  checkEmail: (emailAddress) =>
    api.post(
      '/breach/check-email',
      { email: emailAddress },
      { timeout: 45000 },
    ),
};

export const vuln = {
  fullScan: (target) =>
    api.post(
      '/vuln/full',
      { target },
      {
        timeout: 90000,
      },
    ),

  niktoScan: (target) =>
    api.post(
      '/vuln/nikto',
      { target },
      {
        timeout: 120000,
      },
    ),

  networkCapture: (target) =>
    api.post(
      '/vuln/capture',
      { target },
      {
        timeout: 60000,
      },
    ),
};

export const admin = {
  getUsers: () =>
    api.get('/admin/users'),

  updateRole: (id, role) =>
    api.put(
      `/admin/users/${id}/role`,
      { role },
    ),

  deleteUser: (id) =>
    api.delete(`/admin/users/${id}`),

  getCommunityReports: () =>
    api.get('/admin/community-reports'),

  updateReportStatus: (id, status) =>
    api.put(
      `/admin/community-reports/${id}/status`,
      { status },
    ),

  getStats: () =>
    api.get('/admin/stats'),
};

export const settings = {
  getProfile: () =>
    api.get('/settings/profile'),

  updateProfile: (data) =>
    api.put('/settings/profile', data),

  changePassword: (data) =>
    api.put('/settings/password', data),
};
export const orchestrator = {
  list: () =>
    api.get('/orchestrator/incidents'),

  get: (incidentId) =>
    api.get(`/orchestrator/incidents/${incidentId}`),

  create: (detection) =>
    api.post('/orchestrator/incidents', detection),

  decide: (incidentId, decision) =>
    api.post(
      `/orchestrator/incidents/${incidentId}/decide`,
      decision
    ),

  autoExecute: (incidentId) =>
    api.post(
      `/orchestrator/incidents/${incidentId}/auto-execute`
    ),
};

export const vulnPriority = {
  demo: () =>
    api.get('/vuln-priority/demo'),

  rank: (findings) =>
    api.post('/vuln-priority/rank', findings),
};

export const audit = {
  trail: (incidentId) =>
    api.get('/audit/trail', {
      params: incidentId
        ? { incident_id: incidentId }
        : {},
    }),

  verify: () =>
    api.get('/audit/verify'),
};
export default api;
