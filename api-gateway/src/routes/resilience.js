"use strict";

const express = require("express");

const router = express.Router();

const DETECTION_ENGINE_URL = (
  process.env.DETECTION_ENGINE_URL ||
  process.env.DETECTION_SERVICE_URL ||
  "http://127.0.0.1:8000"
).replace(/\/+$/, "");

const REQUEST_TIMEOUT_MS = Number(
  process.env.DETECTION_ENGINE_TIMEOUT_MS || 15000
);


/**
 * Convert a query object into a URLSearchParams instance.
 *
 * Undefined and null values are omitted so that requests sent to FastAPI
 * remain clean and predictable.
 */
function buildQueryString(query = {}) {
  const searchParams = new URLSearchParams();

  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") {
      continue;
    }

    if (Array.isArray(value)) {
      for (const item of value) {
        searchParams.append(key, String(item));
      }

      continue;
    }

    searchParams.append(key, String(value));
  }

  const queryString = searchParams.toString();

  return queryString ? `?${queryString}` : "";
}


/**
 * Forward one request to the FastAPI detection engine.
 */
async function forwardToDetectionEngine({
  method,
  path,
  body,
  query,
}) {
  const controller = new AbortController();

  const timeout = setTimeout(() => {
    controller.abort();
  }, REQUEST_TIMEOUT_MS);

  const queryString = buildQueryString(query);
  const targetUrl = `${DETECTION_ENGINE_URL}${path}${queryString}`;

  const headers = {
    Accept: "application/json",
  };

  const requestOptions = {
    method,
    headers,
    signal: controller.signal,
  };

  if (
    body !== undefined &&
    body !== null &&
    method !== "GET" &&
    method !== "HEAD"
  ) {
    headers["Content-Type"] = "application/json";
    requestOptions.body = JSON.stringify(body);
  }

  try {
    const response = await fetch(targetUrl, requestOptions);

    const responseText = await response.text();

    let responseData;

    if (!responseText) {
      responseData = null;
    } else {
      try {
        responseData = JSON.parse(responseText);
      } catch {
        responseData = {
          detail: responseText,
        };
      }
    }

    return {
      ok: response.ok,
      status: response.status,
      data: responseData,
      targetUrl,
    };
  } finally {
    clearTimeout(timeout);
  }
}


/**
 * Express route wrapper with consistent gateway error handling.
 */
function createProxyHandler({
  method,
  buildPath,
}) {
  return async function proxyHandler(req, res) {
    try {
      const path = buildPath(req);

      const result = await forwardToDetectionEngine({
        method,
        path,
        body: req.body,
        query: req.query,
      });

      if (!result.ok) {
        return res.status(result.status).json({
          error: "Detection engine request failed",
          upstream_status: result.status,
          upstream_response: result.data,
        });
      }

      return res.status(result.status).json(result.data);
    } catch (error) {
      if (error?.name === "AbortError") {
        return res.status(504).json({
          error: "Detection engine timeout",
          detail:
            "The detection engine did not respond within the configured timeout.",
        });
      }

      console.error(
        "[resilience-proxy] Detection engine request failed:",
        error
      );

      return res.status(502).json({
        error: "Detection engine unavailable",
        detail:
          "The API gateway could not connect to the FastAPI detection engine.",
      });
    }
  };
}


/* -------------------------------------------------------------------------
 * Gateway health
 * ---------------------------------------------------------------------- */

router.get("/health", (req, res) => {
  res.json({
    service: "cybershield-resilience-gateway",
    status: "healthy",
    detection_engine_url: DETECTION_ENGINE_URL,
    execution_mode: "SIMULATED",
  });
});


/* -------------------------------------------------------------------------
 * Vulnerability prioritisation
 * ---------------------------------------------------------------------- */

router.get(
  "/vuln-priority/health",
  createProxyHandler({
    method: "GET",
    buildPath: () => "/api/vuln-priority/health",
  })
);

router.get(
  "/vuln-priority/demo",
  createProxyHandler({
    method: "GET",
    buildPath: () => "/api/vuln-priority/demo",
  })
);

router.post(
  "/vuln-priority/rank",
  createProxyHandler({
    method: "POST",
    buildPath: () => "/api/vuln-priority/rank",
  })
);


/* -------------------------------------------------------------------------
 * Audit integrity
 * ---------------------------------------------------------------------- */

router.get(
  "/audit/health",
  createProxyHandler({
    method: "GET",
    buildPath: () => "/api/audit/health",
  })
);

router.get(
  "/audit/trail",
  createProxyHandler({
    method: "GET",
    buildPath: () => "/api/audit/trail",
  })
);

router.get(
  "/audit/verify",
  createProxyHandler({
    method: "GET",
    buildPath: () => "/api/audit/verify",
  })
);

router.post(
  "/audit/log",
  createProxyHandler({
    method: "POST",
    buildPath: () => "/api/audit/log",
  })
);


/* -------------------------------------------------------------------------
 * Simulated response orchestrator
 * ---------------------------------------------------------------------- */

router.get(
  "/orchestrator/health",
  createProxyHandler({
    method: "GET",
    buildPath: () => "/api/orchestrator/health",
  })
);

router.get(
  "/orchestrator/incidents",
  createProxyHandler({
    method: "GET",
    buildPath: () => "/api/orchestrator/incidents",
  })
);

router.get(
  "/orchestrator/incidents/:incidentId",
  createProxyHandler({
    method: "GET",
    buildPath: (req) =>
      `/api/orchestrator/incidents/${encodeURIComponent(
        req.params.incidentId
      )}`,
  })
);

router.post(
  "/orchestrator/incidents",
  createProxyHandler({
    method: "POST",
    buildPath: () => "/api/orchestrator/incidents",
  })
);

router.post(
  "/orchestrator/incidents/:incidentId/auto-execute",
  createProxyHandler({
    method: "POST",
    buildPath: (req) =>
      `/api/orchestrator/incidents/${encodeURIComponent(
        req.params.incidentId
      )}/auto-execute`,
  })
);

router.post(
  "/orchestrator/incidents/:incidentId/decide",
  createProxyHandler({
    method: "POST",
    buildPath: (req) =>
      `/api/orchestrator/incidents/${encodeURIComponent(
        req.params.incidentId
      )}/decide`,
  })
);


module.exports = router;