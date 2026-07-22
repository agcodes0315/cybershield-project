import axios from 'axios';

/*
 * FastAPI detection-engine client.
 *
 * Existing resilience and response-automation pages may already use
 * /engine/api through the Vite proxy, so this client is preserved.
 */
const resilienceApi = axios.create({
  baseURL:
    import.meta.env.VITE_ENGINE_BASE_URL ||
    '/engine/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

/*
 * Express API Gateway client.
 *
 * The new PS7 endpoints are available through:
 * /api/resilience/*
 */
const resilienceGatewayApi = axios.create({
  baseURL:
    import.meta.env.VITE_API_BASE_URL ||
    '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

function attachAuthentication(client) {
  client.interceptors.request.use(
    (config) => {
      const token = localStorage.getItem('token');

      if (token) {
        config.headers.Authorization =
          `Bearer ${token}`;
      }

      return config;
    },
    (error) => Promise.reject(error),
  );

  client.interceptors.response.use(
    (response) => response,
    (error) => {
      const detail =
        error.response?.data?.detail ||
        error.response?.data?.error ||
        error.response?.data?.message ||
        error.message ||
        'Cyber-resilience request failed.';

      return Promise.reject(
        new Error(detail),
      );
    },
  );
}

attachAuthentication(resilienceApi);
attachAuthentication(resilienceGatewayApi);

/*
 * Existing FastAPI resilience functions.
 */
export const resilience = {
  health: () =>
    resilienceApi.get('/resilience/health'),

  analyse: (payload) =>
    resilienceApi.post(
      '/resilience/analyse',
      payload,
    ),
};

/*
 * New Express Gateway PS7 functions.
 */
export const resilienceGateway = {
  health: () =>
    resilienceGatewayApi.get(
      '/resilience/health',
    ),

  vulnerabilityDemo: () =>
    resilienceGatewayApi.get(
      '/resilience/vuln-priority/demo',
    ),

  prioritiseVulnerabilities: (payload) =>
    resilienceGatewayApi.post(
      '/resilience/vuln-priority',
      payload,
    ),

  orchestratorDemo: () =>
    resilienceGatewayApi.get(
      '/resilience/orchestrator/demo',
    ),

  orchestrateResponse: (payload) =>
    resilienceGatewayApi.post(
      '/resilience/orchestrator',
      payload,
    ),

  auditDemo: () =>
    resilienceGatewayApi.get(
      '/resilience/audit/demo',
    ),

  createAuditRecord: (payload) =>
    resilienceGatewayApi.post(
      '/resilience/audit',
      payload,
    ),

  verifyAudit: () =>
    resilienceGatewayApi.get(
      '/resilience/audit/verify',
    ),
};

/*
 * Existing response-automation functions.
 */
export const responseAutomation = {
  health: () =>
    resilienceApi.get('/response/health'),

  registrySummary: () =>
    resilienceApi.get(
      '/response/registry/summary',
    ),

  listActions: () =>
    resilienceApi.get('/response/actions'),

  listPlaybooks: () =>
    resilienceApi.get(
      '/response/playbooks',
    ),

  recommendPlaybooks: (
    tactic,
    severity,
  ) =>
    resilienceApi.get(
      '/response/recommendations',
      {
        params: {
          tactic,
          severity,
        },
      },
    ),

  listExecutions: () =>
    resilienceApi.get(
      '/response/executions',
    ),

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
        execution_step_id:
          executionStepId,
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
    resilienceApi.get(
      '/response/audit',
    ),

  auditSummary: () =>
    resilienceApi.get(
      '/response/audit/summary',
    ),

  verifyResponseAudit: () =>
    resilienceApi.get(
      '/response/audit/verify',
    ),

  executionAudit: (executionId) =>
    resilienceApi.get(
      `/response/audit/executions/${executionId}`,
    ),
};

export {
  resilienceApi,
  resilienceGatewayApi,
};

export default resilienceApi;