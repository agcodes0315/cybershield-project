"use strict";

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");

const config = require("./config");
const db = require("./config/db");

/*
 * Important:
 * sanitize.js exports sanitizeMiddleware as a named export.
 */
const { sanitizeMiddleware } = require("./middleware/sanitize");

const authRoutes = require("./routes/auth");
const scanRoutes = require("./routes/scan");
const emailRoutes = require("./routes/email");
const threatsRoutes = require("./routes/threats");
const reportsRoutes = require("./routes/reports");
const adminRoutes = require("./routes/admin");
const settingsRoutes = require("./routes/settings");
const communityRoutes = require("./routes/community");
const reconRoutes = require("./routes/recon");
const gophishRoutes = require("./routes/gophish");
const pentestRoutes = require("./routes/pentest");
const vulnRoutes = require("./routes/vuln");
const yaraRoutes = require("./routes/yara");
const breachRoutes = require("./routes/breach");
const shodanRoutes = require("./routes/shodan");
const resilienceRoutes = require("./routes/resilience");

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", 1);

/* -------------------------------------------------------------------------
 * Security middleware
 * ---------------------------------------------------------------------- */

app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy: "cross-origin",
    },
  })
);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) {
        return callback(null, true);
      }

      if (
        config.corsOrigins.includes("*") ||
        config.corsOrigins.includes(origin)
      ) {
        return callback(null, true);
      }

      return callback(
        new Error(`CORS blocked request from origin: ${origin}`)
      );
    },

    methods: [
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS",
    ],

    allowedHeaders: [
      "Content-Type",
      "Authorization",
    ],
  })
);

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 150,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
      error: "Too many requests. Please try again shortly.",
    },
  })
);

/* -------------------------------------------------------------------------
 * Request parsing
 * ---------------------------------------------------------------------- */

app.use(express.json({ limit: "10mb" }));

app.use(
  express.urlencoded({
    extended: true,
    limit: "10mb",
  })
);

/*
 * sanitizeMiddleware is now correctly imported as a function.
 */
app.use(sanitizeMiddleware);

app.use(
  morgan(
    config.nodeEnv === "production"
      ? "combined"
      : "dev"
  )
);

/* -------------------------------------------------------------------------
 * Gateway status routes
 * ---------------------------------------------------------------------- */

app.get("/", (req, res) => {
  return res.json({
    service: "CyberShield API Gateway",
    status: "running",
    health: "/health",
    resilience_health: "/api/resilience/health",
    detection_engine: config.detectionEngineUrl,
  });
});

app.get("/health", async (req, res) => {
  try {
    await db.testConnection();

    return res.status(200).json({
      status: "healthy",
      service: "api-gateway",
      database: "connected",
      detection_engine: config.detectionEngineUrl,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("[HEALTH ERROR]", error);

    return res.status(503).json({
      status: "unhealthy",
      service: "api-gateway",
      database: "disconnected",
      detection_engine: config.detectionEngineUrl,
      error: error.message,
      timestamp: new Date().toISOString(),
    });
  }
});

app.get("/health/live", (req, res) => {
  return res.status(200).json({
    status: "alive",
    service: "api-gateway",
    timestamp: new Date().toISOString(),
  });
});

/* -------------------------------------------------------------------------
 * Existing application routes
 * ---------------------------------------------------------------------- */

app.use("/api/auth", authRoutes);
app.use("/api/scan", scanRoutes);
app.use("/api/email", emailRoutes);
app.use("/api/threats", threatsRoutes);
app.use("/api/reports", reportsRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/settings", settingsRoutes);
app.use("/api/community", communityRoutes);
app.use("/api/recon", reconRoutes);
app.use("/api/gophish", gophishRoutes);
app.use("/api/pentest", pentestRoutes);
app.use("/api/vuln", vulnRoutes);
app.use("/api/yara", yaraRoutes);
app.use("/api/breach", breachRoutes);
app.use("/api/shodan", shodanRoutes);

/* -------------------------------------------------------------------------
 * PS7 resilience routes
 * ---------------------------------------------------------------------- */

app.use("/api/resilience", resilienceRoutes);

/* -------------------------------------------------------------------------
 * 404 handler
 * ---------------------------------------------------------------------- */

app.use((req, res) => {
  return res.status(404).json({
    error: "Route not found",
    method: req.method,
    path: req.originalUrl,
  });
});

/* -------------------------------------------------------------------------
 * Global error handler
 * ---------------------------------------------------------------------- */

app.use((error, req, res, next) => {
  console.error("[API ERROR]", error);

  if (error.message?.startsWith("CORS blocked")) {
    return res.status(403).json({
      error: error.message,
    });
  }

  if (error instanceof SyntaxError && error.status === 400) {
    return res.status(400).json({
      error: "Invalid JSON request body",
    });
  }

  return res.status(error.status || 500).json({
    error: error.message || "Internal server error",
  });
});

module.exports = app;