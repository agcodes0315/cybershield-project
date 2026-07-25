import axios from "axios";

const DEFAULT_API_BASE_URL =
  "https://cybershield-api-gateway.niceforest-87cbfff3.centralindia.azurecontainerapps.io/api";

function normalizeBaseUrl(value) {
  const url = String(
    value || DEFAULT_API_BASE_URL,
  ).trim();

  return url.replace(/\/+$/, "");
}

/*
 * Use one consistent localStorage key throughout the application.
 */
const TOKEN_STORAGE_KEY =
  "cybershield_token";

const USER_STORAGE_KEY =
  "cybershield_user";

export function saveAuthSession(
  token,
  user = null,
) {
  if (!token) {
    throw new Error(
      "Cannot save authentication session without a token.",
    );
  }

  const cleanToken = String(token)
    .replace(/^Bearer\s+/i, "")
    .trim();

  localStorage.setItem(
    TOKEN_STORAGE_KEY,
    cleanToken,
  );

  if (user) {
    localStorage.setItem(
      USER_STORAGE_KEY,
      JSON.stringify(user),
    );
  }
}

export function clearAuthSession() {
  localStorage.removeItem(
    TOKEN_STORAGE_KEY,
  );

  localStorage.removeItem(
    USER_STORAGE_KEY,
  );

  /*
   * Remove old token keys that may contain
   * stale or invalid authentication data.
   */
  const legacyKeys = [
    "token",
    "accessToken",
    "access_token",
    "jwt",
    "authToken",
    "auth",
    "user",
    "cybershield-auth",
    "cybershieldAuth",
  ];

  legacyKeys.forEach((key) => {
    localStorage.removeItem(key);
  });
}

export function getStoredToken() {
  const primaryToken =
    localStorage.getItem(
      TOKEN_STORAGE_KEY,
    );

  if (
    primaryToken &&
    primaryToken !== "null" &&
    primaryToken !== "undefined"
  ) {
    return primaryToken
      .replace(/^Bearer\s+/i, "")
      .trim();
  }

  /*
   * Temporary compatibility with older
   * frontend authentication versions.
   */
  const directKeys = [
    "token",
    "accessToken",
    "access_token",
    "jwt",
    "authToken",
  ];

  for (const key of directKeys) {
    const value =
      localStorage.getItem(key);

    if (
      value &&
      value !== "null" &&
      value !== "undefined"
    ) {
      return value
        .replace(/^Bearer\s+/i, "")
        .trim();
    }
  }

  const objectKeys = [
    "auth",
    "user",
    "cybershield-auth",
    "cybershieldAuth",
  ];

  for (const key of objectKeys) {
    const rawValue =
      localStorage.getItem(key);

    if (!rawValue) {
      continue;
    }

    try {
      const parsed =
        JSON.parse(rawValue);

      const token =
        parsed?.token ||
        parsed?.accessToken ||
        parsed?.access_token ||
        parsed?.jwt ||
        parsed?.authToken ||
        parsed?.data?.token ||
        parsed?.data?.accessToken ||
        parsed?.data?.access_token ||
        parsed?.user?.token;

      if (token) {
        return String(token)
          .replace(/^Bearer\s+/i, "")
          .trim();
      }
    } catch {
      /*
       * Ignore non-JSON localStorage values.
       */
    }
  }

  return null;
}

export function getStoredUser() {
  const rawUser =
    localStorage.getItem(
      USER_STORAGE_KEY,
    );

  if (!rawUser) {
    return null;
  }

  try {
    return JSON.parse(rawUser);
  } catch {
    return null;
  }
}

const api = axios.create({
  baseURL: normalizeBaseUrl(
    import.meta.env.VITE_API_BASE_URL,
  ),

  timeout: 30000,

  headers: {
    Accept: "application/json",
    "Content-Type":
      "application/json",
  },
});

/*
 * Attach JWT token to authenticated requests.
 */
api.interceptors.request.use(
  (config) => {
    const token = getStoredToken();

    config.headers =
      config.headers || {};

    if (token) {
      config.headers.Authorization =
        `Bearer ${token}`;
    } else {
      delete config.headers.Authorization;
    }

    return config;
  },

  (error) =>
    Promise.reject(error),
);

/*
 * Central API error handling.
 */
api.interceptors.response.use(
  (response) => response,

  (error) => {
    const status =
      error?.response?.status;

    console.error(
      "[CyberShield API Error]",
      {
        method:
          error?.config?.method,

        url:
          error?.config?.url,

        baseURL:
          error?.config?.baseURL,

        status,

        tokenFound:
          Boolean(getStoredToken()),

        response:
          error?.response?.data,

        message:
          error?.message,
      },
    );

    /*
     * Do not remove the token for failed login attempts.
     * Clear it only when a protected request rejects
     * an existing token.
     */
    const isLoginRequest =
      error?.config?.url?.includes(
        "/auth/login",
      );

    if (
      status === 401 &&
      !isLoginRequest &&
      getStoredToken()
    ) {
      clearAuthSession();

      window.dispatchEvent(
        new CustomEvent(
          "cybershield:unauthorized",
        ),
      );
    }

    return Promise.reject(error);
  },
);

/*
 * Authentication
 */
export const auth = {
  register: (data) =>
    api.post(
      "/auth/register",
      data,
    ),

  login: (data) =>
    api.post(
      "/auth/login",
      data,
    ),

  me: () =>
    api.get("/auth/me"),
};

/*
 * URL scanning
 */
export const scan = {
  url: (url) =>
    api.post(
      "/scan/url",
      { url },
    ),

  history: () =>
    api.get("/scan/history"),
};

/*
 * Email analysis
 */
export const email = {
  analyze: (rawHeaders) =>
    api.post(
      "/email/analyze",
      {
        raw_headers:
          rawHeaders,
      },
    ),
};

/*
 * Threat intelligence
 */
export const threats = {
  recent: () =>
    api.get(
      "/threats/recent",
    ),

  fetchFeeds: () =>
    api.post(
      "/threats/fetch",
    ),
};

/*
 * MITRE ATT&CK mappings
 */
export const mitre = {
  getMappings: () =>
    api.get("/mitre"),
};

/*
 * Community reporting
 */
export const community = {
  getReports: () =>
    api.get(
      "/community/reports",
    ),

  submitReport: (data) =>
    api.post(
      "/community/report",
      data,
    ),

  vote: (id, type) =>
    api.post(
      `/community/report/${id}/vote`,
      { type },
    ),
};

/*
 * PDF reports
 */
export const reports = {
  generate: async (
    scanData,
  ) => {
    const response =
      await api.post(
        "/reports/generate",
        scanData,
        {
          responseType: "blob",
          timeout: 60000,
        },
      );

    const blob =
      new Blob(
        [response.data],
        {
          type:
            "application/pdf",
        },
      );

    const objectUrl =
      window.URL.createObjectURL(
        blob,
      );

    const link =
      document.createElement(
        "a",
      );

    link.href = objectUrl;

    link.download =
      `cybershield_report_${Date.now()}.pdf`;

    document.body.appendChild(
      link,
    );

    link.click();

    document.body.removeChild(
      link,
    );

    window.URL.revokeObjectURL(
      objectUrl,
    );
  },
};

/*
 * Reconnaissance
 */
export const recon = {
  portScan: (domain) =>
    api.post(
      "/recon/port-scan",
      { domain },
      {
        timeout: 60000,
      },
    ),

  abuseCheck: (domain) =>
    api.post(
      "/recon/abuse-check",
      { domain },
      {
        timeout: 45000,
      },
    ),

  full: (domain) =>
    api.post(
      "/recon/full",
      { domain },
      {
        timeout: 90000,
      },
    ),
};

/*
 * GoPhish integration
 */
export const gophish = {
  getCampaigns: () =>
    api.get(
      "/gophish/campaigns",
    ),

  getCampaign: (id) =>
    api.get(
      `/gophish/campaigns/${id}`,
    ),

  getPages: () =>
    api.get(
      "/gophish/pages",
    ),

  getTemplates: () =>
    api.get(
      "/gophish/templates",
    ),

  analyzeUrl: (url) =>
    api.post(
      "/gophish/analyze-url",
      { url },
      {
        timeout: 60000,
      },
    ),
};

/*
 * YARA scanning
 */
export const yaraScan = {
  scan: (url) =>
    api.post(
      "/yara/scan",
      { url },
      {
        timeout: 60000,
      },
    ),

  getRules: () =>
    api.get(
      "/yara/rules",
    ),
};

/*
 * Breach analysis
 */
export const breach = {
  checkPassword: (
    password,
  ) =>
    api.post(
      "/breach/check-password",
      { password },
      {
        timeout: 45000,
      },
    ),

  checkEmail: (
    emailAddress,
  ) =>
    api.post(
      "/breach/check-email",
      {
        email:
          emailAddress,
      },
      {
        timeout: 45000,
      },
    ),
};

/*
 * Vulnerability scanning
 */
export const vuln = {
  fullScan: (target) =>
    api.post(
      "/vuln/full",
      { target },
      {
        timeout: 90000,
      },
    ),

  niktoScan: (target) =>
    api.post(
      "/vuln/nikto",
      { target },
      {
        timeout: 120000,
      },
    ),

  networkCapture: (
    target,
  ) =>
    api.post(
      "/vuln/capture",
      { target },
      {
        timeout: 60000,
      },
    ),
};

/*
 * Administration
 */
export const admin = {
  getUsers: () =>
    api.get(
      "/admin/users",
    ),

  updateRole: (
    id,
    role,
  ) =>
    api.put(
      `/admin/users/${id}/role`,
      { role },
    ),

  deleteUser: (id) =>
    api.delete(
      `/admin/users/${id}`,
    ),

  getCommunityReports: () =>
    api.get(
      "/admin/community-reports",
    ),

  updateReportStatus: (
    id,
    status,
  ) =>
    api.put(
      `/admin/community-reports/${id}/status`,
      { status },
    ),

  getStats: () =>
    api.get(
      "/admin/stats",
    ),
};

/*
 * Account settings
 */
export const settings = {
  getProfile: () =>
    api.get(
      "/settings/profile",
    ),

  updateProfile: (data) =>
    api.put(
      "/settings/profile",
      data,
    ),

  changePassword: (data) =>
    api.put(
      "/settings/password",
      data,
    ),
};

/*
 * Cyber-resilience response orchestrator
 */
export const orchestrator = {
  list: () =>
    api.get(
      "/resilience/orchestrator/incidents",
    ),

  get: (incidentId) =>
    api.get(
      `/resilience/orchestrator/incidents/${incidentId}`,
    ),

  create: (detection) =>
    api.post(
      "/resilience/orchestrator/incidents",
      detection,
    ),

  decide: (
    incidentId,
    decision,
  ) =>
    api.post(
      `/resilience/orchestrator/incidents/${incidentId}/decide`,
      decision,
    ),

  autoExecute: (
    incidentId,
  ) =>
    api.post(
      `/resilience/orchestrator/incidents/${incidentId}/auto-execute`,
    ),
};

/*
 * Vulnerability prioritisation
 */
export const vulnPriority = {
  demo: () =>
    api.get(
      "/resilience/vuln-priority/demo",
    ),

  rank: (findings) =>
    api.post(
      "/resilience/vuln-priority/rank",
      findings,
    ),
};

/*
 * Tamper-evident audit trail
 */
export const audit = {
  trail: (incidentId) =>
    api.get(
      "/resilience/audit/trail",
      {
        params: incidentId
          ? {
              incident_id:
                incidentId,
            }
          : {},
      },
    ),

  verify: () =>
    api.get(
      "/resilience/audit/verify",
    ),
};

export default api;