const { WebSocketServer, WebSocket } = require("ws");
const jwt = require("jsonwebtoken");
const config = require("../config");

function setupWebSocket(server) {
  const wss = new WebSocketServer({
    server,
    path: "/ws",
  });

  wss.on("connection", (ws, req) => {
    try {
      const requestUrl = new URL(
        req.url,
        `http://${req.headers.host || "localhost"}`
      );

      const token = requestUrl.searchParams.get("token");

      ws.isAuthenticated = false;

      if (token) {
        try {
          const decoded = jwt.verify(
            token,
            config.jwtSecret
          );

          ws.userId = decoded.id;
          ws.userEmail = decoded.email;
          ws.isAuthenticated = true;
        } catch (error) {
          console.error(
            "[WS AUTH ERROR]",
            error.message
          );
        }
      }

      console.log(
        `[WS] Client connected, authenticated=${ws.isAuthenticated}`
      );

      ws.on("message", (message) => {
        try {
          const data = JSON.parse(
            message.toString()
          );

          if (data.type === "ping") {
            ws.send(
              JSON.stringify({
                type: "pong",
                timestamp: new Date().toISOString(),
              })
            );
          }
        } catch (error) {
          ws.send(
            JSON.stringify({
              type: "error",
              message: "Invalid WebSocket message",
            })
          );
        }
      });

      ws.on("error", (error) => {
        console.error("[WS CLIENT ERROR]", error);
      });

      ws.on("close", () => {
        console.log("[WS] Client disconnected");
      });

      ws.send(
        JSON.stringify({
          type: "connected",
          authenticated: ws.isAuthenticated,
          message: "CyberShield WebSocket connected",
          timestamp: new Date().toISOString(),
        })
      );
    } catch (error) {
      console.error("[WS CONNECTION ERROR]", error);
      ws.close();
    }
  });

  return wss;
}

function broadcast(wss, event) {
  if (!wss) {
    return;
  }

  const payload = JSON.stringify(event);

  for (const client of wss.clients) {
    if (
      client.readyState === WebSocket.OPEN &&
      client.isAuthenticated
    ) {
      client.send(payload);
    }
  }
}

function broadcastToUser(wss, userId, event) {
  if (!wss) {
    return;
  }

  const payload = JSON.stringify(event);

  for (const client of wss.clients) {
    if (
      client.readyState === WebSocket.OPEN &&
      String(client.userId) === String(userId)
    ) {
      client.send(payload);
    }
  }
}

module.exports = {
  setupWebSocket,
  broadcast,
  broadcastToUser,
};
