"use strict";

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");

const config = require("./config");
const db = require("./config/db");

const {
  sanitizeMiddleware,
} = require("./middleware/sanitize");

const authRoutes = require("./routes/auth");
const scanRoutes = require("./routes/scan");
const emailRoutes = require("./routes/email");
const threatsRoutes = require("./routes/threats");
const mitreRoutes = require("./routes/mitre");
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

const productionFrontend =
  "https://mango-pebble-099d8de00.7.azurestaticapps.net";

const allowedOrigins = [
  productionFrontend,
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  ...(Array.isArray(config.corsOrigins)
    ? config.corsOrigins
    : []),
];

/*
 * Security middleware
 */

app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy: "cross-origin",
    },
  }),
);

/*
 * CORS configuration
 */

const corsOptions = {
  origin(origin, callback) {
    /*
     * Requests without an Origin header include health checks,
     * curl, Postman and server-to-server requests.
     */
    if (!origin) {
      return callback(null, true);
    }

    if (
      allowedOrigins.includes("*") ||
      allowedOrigins.includes(origin)
    ) {
      return callback(null, true);
    }

    console.error(
      `[CORS] Blocked origin: ${origin}`,
    );

    return callback(
      new Error(
        `CORS blocked request from origin: ${origin}`,
      ),
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
    "Accept",
    "Origin",
    "X-Requested-With",
  ],

  exposedHeaders: [
    "Content-Length",
    "Content-Type",
  ],

  credentials: false,

  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));

/*
 * Rate limiting
 */

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 150,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
      error:
        "Too many requests. Please try again shortly.",
    },
  }),
);

/*
 * Request parsing
 */

app.use(
  express.json({
    limit: "10mb",
  }),
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "10mb",
  }),
);

/*
 * Request sanitisation and logging
 */

app.use(sanitizeMiddleware);

app.use(
  morgan(
    config.nodeEnv === "production"
      ? "combined"
      : "dev",
  ),
);

/*
 * Health endpoints
 */

app.get("/", (req, res) => {
  return res.status(200).json({
    service: "CyberShield API Gateway",
    status: "running",
    health: "/health",
    live: "/health/live",
    detection_engine:
      config.detectionEngineUrl,
  });
});

app.get("/health/live", (req, res) => {
  return res.status(200).json({
    status: "alive",
    service: "api-gateway",
    timestamp: new Date().toISOString(),
  });
});

app.get("/health", async (req, res) => {
  try {
    await db.testConnection();

    return res.status(200).json({
      status: "healthy",
      service: "api-gateway",
      database: "connected",
      detection_engine:
        config.detectionEngineUrl,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error(
      "[HEALTH ERROR]",
      error,
    );

    return res.status(503).json({
      status: "unhealthy",
      service: "api-gateway",
      database: "disconnected",
      detection_engine:
        config.detectionEngineUrl,
      error: error.message,
      timestamp: new Date().toISOString(),
    });
  }
});

/*
 * Application routes
 */

app.use("/api/auth", authRoutes);
app.use("/api/scan", scanRoutes);
app.use("/api/email", emailRoutes);
app.use("/api/threats", threatsRoutes);
app.use("/api/mitre", mitreRoutes);
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

app.use(
  "/api/resilience",
  resilienceRoutes,
);

/*
 * Unknown route handler
 */

app.use((req, res) => {
  return res.status(404).json({
    error: "Route not found",
    method: req.method,
    path: req.originalUrl,
  });
});

/*
 * Global error handler
 */

app.use(
  (error, req, res, next) => {
    console.error("[API ERROR]", error);

    if (
      error.message?.startsWith(
        "CORS blocked",
      )
    ) {
      return res.status(403).json({
        error: error.message,
      });
    }

    if (
      error instanceof SyntaxError &&
      error.status === 400
    ) {
      return res.status(400).json({
        error:
          "Invalid JSON request body",
      });
    }

    return res
      .status(error.status || 500)
      .json({
        error:
          error.message ||
          "Internal server error",
      });
  },
);

module.exports = app;