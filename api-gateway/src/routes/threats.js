const express = require("express");
const db = require("../config/db");
const authenticate = require("../middleware/auth");
const {
  fetchDetectionEngine,
  readJsonResponse,
} = require("../utils/detectionProxy");

const router = express.Router();

async function fetchAndStoreThreats(req, res) {
  try {
    const response = await fetchDetectionEngine(
      "/api/threats/feeds/fetch"
    );

    const data = await readJsonResponse(response);

    if (!response.ok) {
      return res.status(response.status).json(data);
    }

    const entries = Array.isArray(data.entries)
      ? data.entries
      : [];

    let stored = 0;
    let failed = 0;

    for (const entry of entries) {
      try {
        if (!entry?.url) {
          failed += 1;
          continue;
        }

        const result = await db.query(
          `
          INSERT INTO threat_entries (
            url,
            source,
            threat_type,
            confidence,
            first_seen,
            last_seen,
            metadata
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            NOW(),
            $6::jsonb
          )
          ON CONFLICT (url, source)
          DO UPDATE SET
            threat_type = EXCLUDED.threat_type,
            confidence = EXCLUDED.confidence,
            last_seen = NOW(),
            metadata = EXCLUDED.metadata
          RETURNING id
          `,
          [
            String(entry.url).trim(),
            entry.source || "unknown",
            entry.threat_type || "unknown",
            Number(entry.confidence || 0),
            entry.first_seen || new Date(),
            JSON.stringify(entry.metadata || {}),
          ]
        );

        if (result.rows.length > 0) {
          stored += 1;
        }
      } catch (error) {
        failed += 1;

        console.error(
          "[THREAT STORE ERROR]",
          entry?.url || "unknown",
          error.message
        );
      }
    }

    return res.json({
      total_fetched: data.total || entries.length,
      stored,
      failed,
      message:
        data.message || "Threat feeds processed successfully",
    });
  } catch (error) {
    console.error("[THREAT FETCH ERROR]", error);

    return res.status(502).json({
      error: "Failed to fetch threat feeds",
      detail: error.message,
    });
  }
}

router.post(
  "/fetch",
  authenticate,
  fetchAndStoreThreats
);

router.get(
  "/search",
  authenticate,
  async (req, res) => {
    try {
      const url = String(
        req.query.url || ""
      ).trim();

      if (!url) {
        return res.status(400).json({
          error:
            "url query parameter is required",
        });
      }

      const result = await db.query(
        `
        SELECT *
        FROM threat_entries
        WHERE url ILIKE $1
        ORDER BY last_seen DESC
        LIMIT 20
        `,
        [`%${url}%`]
      );

      return res.json({
        query: url,
        count: result.rows.length,
        entries: result.rows,
      });
    } catch (error) {
      console.error(
        "[THREAT SEARCH ERROR]",
        error
      );

      return res.status(500).json({
        error: "Threat search failed",
      });
    }
  }
);

router.get(
  "/recent",
  authenticate,
  async (req, res) => {
    try {
      const result = await db.query(
        `
        SELECT *
        FROM threat_entries
        ORDER BY last_seen DESC
        LIMIT 50
        `
      );

      return res.json(result.rows);
    } catch (error) {
      console.error(
        "[RECENT THREATS ERROR]",
        error
      );

      return res.status(500).json({
        error:
          "Failed to fetch recent threats",
      });
    }
  }
);

module.exports = router;