"use strict";

const http = require("http");

const app = require("./app");
const config = require("./config");
const db = require("./config/db");

const {
  setupWebSocket,
} = require("./websocket/ws");

const server = http.createServer(app);

const wss = setupWebSocket(server);
app.set("wss", wss);

const port =
  Number(process.env.PORT) ||
  Number(config.port) ||
  5000;

server.listen(
  port,
  "0.0.0.0",
  async () => {
    console.log(
      `[CyberShield API] Running on 0.0.0.0:${port}`,
    );

    console.log(
      "[CyberShield WS] WebSocket available at /ws",
    );

    console.log(
      `[CyberShield Detection] ${config.detectionEngineUrl}`,
    );

    try {
      await db.testConnection();

      console.log(
        "[CyberShield DB] PostgreSQL connection verified",
      );
    } catch (error) {
      console.error(
        "[CyberShield DB] PostgreSQL connection failed:",
        error.message,
      );
    }
  },
);

async function shutdown(signal) {
  console.log(
    `[CyberShield API] Received ${signal}. Shutting down.`,
  );

  server.close(async () => {
    try {
      await db.pool.end();
    } catch (error) {
      console.error(
        "[CyberShield DB] Shutdown error:",
        error,
      );
    }

    process.exit(0);
  });

  setTimeout(() => {
    console.error(
      "[CyberShield API] Forced shutdown after timeout.",
    );

    process.exit(1);
  }, 10000).unref();
}

process.on(
  "SIGTERM",
  () => shutdown("SIGTERM"),
);

process.on(
  "SIGINT",
  () => shutdown("SIGINT"),
);