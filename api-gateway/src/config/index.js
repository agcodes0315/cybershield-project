require("dotenv").config();

function readBoolean(value, defaultValue = false) {
  if (value === undefined || value === null || value === "") {
    return defaultValue;
  }

  return ["true", "1", "yes", "on"].includes(
    String(value).toLowerCase()
  );
}

module.exports = {
  nodeEnv: process.env.NODE_ENV || "development",

  port: Number(process.env.PORT || 5000),

  jwtSecret:
    process.env.JWT_SECRET ||
    "development-secret-change-before-production",

  detectionEngineUrl:
    process.env.DETECTION_ENGINE_URL ||
    "http://127.0.0.1:8000",

  corsOrigins: process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN
        .split(",")
        .map((origin) => origin.trim())
        .filter(Boolean)
    : ["http://127.0.0.1:5173", "http://localhost:5173"],

  db: {
    host: process.env.DB_HOST || "localhost",
    port: Number(process.env.DB_PORT || 5432),
    name: process.env.DB_NAME || "cybershield",
    user: process.env.DB_USER || "postgres",
    password: process.env.DB_PASSWORD || "postgres",
    ssl: readBoolean(process.env.DB_SSL, false),
  },

  redis: {
    host: process.env.REDIS_HOST || "localhost",
    port: Number(process.env.REDIS_PORT || 6379),
  },
};
