const express = require("express");
const db = require("../config/db");
const authenticate = require("../middleware/auth");
const {
  fetchDetectionEngine,
  readJsonResponse,
} = require("../utils/detectionProxy");

const router = express.Router();

router.post("/analyze", authenticate, async (req, res) => {
  try {
    const rawHeaders = req.body.raw_headers;

    if (!rawHeaders) {
      return res.status(400).json({
        error: "raw_headers is required",
      });
    }

    const response = await fetchDetectionEngine(
      "/api/email/analyze",
      {
        method: "POST",
        body: {
          raw_headers: rawHeaders,
        },
      }
    );

    const result = await readJsonResponse(response);

    if (!response.ok) {
      return res.status(response.status).json(result);
    }

    const dbResult = await db.query(
      `
      INSERT INTO email_analyses (
        raw_headers,
        sender_ip,
        from_domain,
        spf_result,
        dkim_result,
        dmarc_result,
        is_spoofed,
        analyzed_by
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
      `,
      [
        rawHeaders,
        result.sender_ip || null,
        result.from_domain || null,
        result.spf_result || null,
        result.dkim_result || null,
        result.dmarc_result || null,
        Boolean(result.is_spoofed),
        req.user.id,
      ]
    );

    return res.json({
      ...result,
      id: dbResult.rows[0].id,
    });
  } catch (error) {
    console.error("[EMAIL ANALYSIS ERROR]", error);

    return res.status(502).json({
      error: "Email analysis failed",
      detail: error.message,
    });
  }
});

module.exports = router;
