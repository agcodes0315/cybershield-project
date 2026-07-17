import axios from 'axios';

const resilienceApi = axios.create({
  baseURL: '/engine/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

resilienceApi.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');

    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    return config;
  },
  (error) => Promise.reject(error),
);

resilienceApi.interceptors.response.use(
  (response) => response,
  (error) => {
    const detail =
      error.response?.data?.detail ||
      error.response?.data?.message ||
      error.message ||
      'Cyber-resilience request failed.';

    return Promise.reject(new Error(detail));
  },
);

export const resilience = {
  health: () =>
    resilienceApi.get('/resilience/health'),

  analyse: (payload) =>
    resilienceApi.post('/resilience/analyse', payload),
};

export const responseAutomation = {
  health: () =>
    resilienceApi.get('/response/health'),

  registrySummary: () =>
    resilienceApi.get('/response/registry/summary'),

  listActions: () =>
    resilienceApi.get('/response/actions'),

  listPlaybooks: () =>
    resilienceApi.get('/response/playbooks'),

  recommendPlaybooks: (tactic, severity) =>
    resilienceApi.get('/response/recommendations', {
      params: {
        tactic,
        severity,
      },
    }),

  listExecutions: () =>
    resilienceApi.get('/response/executions'),

  getExecution: (executionId) =>
    resilienceApi.get(
      `/response/executions/${executionId}`,
    ),

  getApprovalStates: (executionId) =>
    resilienceApi.get(
      `/response/executions/${executionId}/approvals`,
    ),

  submitApproval: (
    executionId,
    executionStepId,
    approverId,
    approved,
    reason,
  ) =>
    resilienceApi.post(
      `/response/executions/${executionId}/approve`,
      {
        execution_step_id: executionStepId,
        approver_id: approverId,
        approved,
        reason,
      },
    ),

  execute: (executionId) =>
    resilienceApi.post(
      `/response/executions/${executionId}/execute`,
    ),

  auditRecords: () =>
    resilienceApi.get('/response/audit'),

  auditSummary: () =>
    resilienceApi.get('/response/audit/summary'),

  verifyAudit: () =>
    resilienceApi.get('/response/audit/verify'),

  executionAudit: (executionId) =>
    resilienceApi.get(
      `/response/audit/executions/${executionId}`,
    ),
};

export default resilienceApi;