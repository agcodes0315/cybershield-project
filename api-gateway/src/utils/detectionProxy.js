const config = require("../config");

function createDetectionUrl(endpoint) {
  const baseUrl = config.detectionEngineUrl.replace(/\/+$/, "");
  const path = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;

  return `${baseUrl}${path}`;
}

async function fetchDetectionEngine(endpoint, options = {}) {
  const controller = new AbortController();

  const timeout = setTimeout(() => {
    controller.abort();
  }, Number(options.timeout || 120000));

  try {
    const response = await fetch(createDetectionUrl(endpoint), {
      method: options.method || "GET",

      headers: {
        Accept: "application/json",
        ...(options.body !== undefined
          ? { "Content-Type": "application/json" }
          : {}),
        ...(options.headers || {}),
      },

      body:
        options.body !== undefined
          ? JSON.stringify(options.body)
          : undefined,

      signal: controller.signal,
    });

    return response;
  } finally {
    clearTimeout(timeout);
  }
}

async function readJsonResponse(response) {
  const contentType = response.headers.get("content-type") || "";

  if (contentType.includes("application/json")) {
    return response.json();
  }

  const text = await response.text();

  return {
    error: text || `Detection Engine returned HTTP ${response.status}`,
  };
}

async function proxyJson(res, endpoint, options = {}) {
  try {
    const response = await fetchDetectionEngine(endpoint, options);
    const result = await readJsonResponse(response);

    return res.status(response.status).json(result);
  } catch (error) {
    console.error(`[DETECTION PROXY ERROR] ${endpoint}`, error);

    if (error.name === "AbortError") {
      return res.status(504).json({
        error: "Detection Engine request timed out",
      });
    }

    return res.status(502).json({
      error: "Unable to connect to the Detection Engine",
      detail: error.message,
    });
  }
}

module.exports = {
  createDetectionUrl,
  fetchDetectionEngine,
  readJsonResponse,
  proxyJson,
};
