const express = require("express");
const db = require("../config/db");
const authenticate = require("../middleware/auth");
const {
  fetchDetectionEngine,
  readJsonResponse,
} = require("../utils/detectionProxy");
const {
  broadcast,
  broadcastToUser,
} = require("../websocket/ws");

const router = express.Router();

router.post("/url", authenticate, async (req, res) => {
  try {
    const url = String(req.body.url || "").trim();

    if (!url) {
      return res.status(400).json({
        error: "URL is required",
      });
    }

    const response = await fetchDetectionEngine(
      "/api/scan/url",
      {
        method: "POST",
        body: { url },
        timeout: 180000,
      }
    );

    const scanResult = await readJsonResponse(response);

    if (!response.ok) {
      return res.status(response.status).json(scanResult);
    }

    const result = await db.query(
      `
      INSERT INTO url_scans (
        url,
        domain,
        threat_score,
        is_malicious,
        scan_source,
        features,
        whois_data,
        ssl_info,
        scanned_by
      )
      VALUES (
        $1,
        $2,
        $3,
        $4,
        $5,
        $6::jsonb,
        $7::jsonb,
        $8::jsonb,
        $9
      )
      RETURNING *
      `,
      [
        url,
        scanResult.domain || null,
        Number(scanResult.threat_score || 0),
        Boolean(scanResult.is_malicious),
        "user",
        JSON.stringify(scanResult.features || {}),
        JSON.stringify(scanResult.whois_data || {}),
        JSON.stringify(scanResult.ssl_info || {}),
        req.user.id,
      ]
    );

    const savedScan = result.rows[0];
    const wss = req.app.get("wss");

    broadcastToUser(wss, req.user.id, {
      type: "scan_complete",
      data: {
        id: savedScan.id,
        url: savedScan.url,
        domain: savedScan.domain,
        threat_score: scanResult.threat_score,
        is_malicious: scanResult.is_malicious,
        ml_prediction:
          scanResult.ml_analysis?.ensemble_prediction ||
          "unknown",
        timestamp: savedScan.created_at,
      },
    });

    if (scanResult.is_malicious) {
      broadcast(wss, {
        type: "threat_alert",
        data: {
          url: savedScan.url,
          domain: savedScan.domain,
          threat_score: scanResult.threat_score,
          ml_prediction:
            scanResult.ml_analysis?.ensemble_prediction ||
            "unknown",
          message: `Malicious URL detected: ${savedScan.domain}`,
          timestamp: new Date().toISOString(),
        },
      });
    }

    return res.json({
      ...savedScan,
      ...scanResult,
    });
  } catch (error) {
    console.error("[URL SCAN ERROR]", error);

    return res.status(502).json({
      error: "Scan failed",
      detail: error.message,
    });
  }
});

router.get("/history", authenticate, async (req, res) => {
  try {
    const result = await db.query(
      `
      SELECT *
      FROM url_scans
      WHERE scanned_by = $1
      ORDER BY created_at DESC
      LIMIT 50
      `,
      [req.user.id]
    );

    return res.json(result.rows);
  } catch (error) {
    console.error("[SCAN HISTORY ERROR]", error);

    return res.status(500).json({
      error: "Failed to fetch scan history",
    });
  }
});

module.exports = router;
