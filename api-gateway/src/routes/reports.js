const express = require("express");
const authenticate = require("../middleware/auth");
const {
  fetchDetectionEngine,
  readJsonResponse,
} = require("../utils/detectionProxy");

const router = express.Router();

router.post("/generate", authenticate, async (req, res) => {
  try {
    const response = await fetchDetectionEngine(
      "/api/reports/generate",
      {
        method: "POST",
        body: req.body,
        timeout: 180000,
      }
    );

    if (!response.ok) {
      const result = await readJsonResponse(response);

      return res.status(response.status).json(result);
    }

    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    res.setHeader("Content-Type", "application/pdf");

    res.setHeader(
      "Content-Disposition",
      'attachment; filename="cybershield_report.pdf"'
    );

    return res.send(buffer);
  } catch (error) {
    console.error("[REPORT GENERATION ERROR]", error);

    return res.status(502).json({
      error: "Report generation failed",
      detail: error.message,
    });
  }
});

module.exports = router;
