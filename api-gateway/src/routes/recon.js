const express = require("express");
const authenticate = require("../middleware/auth");
const { proxyJson } = require("../utils/detectionProxy");

const router = express.Router();

function validateDomain(req, res) {
  const domain = String(req.body.domain || "").trim();

  if (!domain) {
    res.status(400).json({
      error: "Domain is required",
    });

    return null;
  }

  return domain;
}

router.post("/port-scan", authenticate, async (req, res) => {
  const domain = validateDomain(req, res);

  if (!domain) {
    return;
  }

  return proxyJson(
    res,
    "/api/recon/port-scan",
    {
      method: "POST",
      body: { domain },
      timeout: 180000,
    }
  );
});

router.post("/abuse-check", authenticate, async (req, res) => {
  const domain = validateDomain(req, res);

  if (!domain) {
    return;
  }

  return proxyJson(
    res,
    "/api/recon/abuse-check",
    {
      method: "POST",
      body: { domain },
    }
  );
});

router.post("/full", authenticate, async (req, res) => {
  const domain = validateDomain(req, res);

  if (!domain) {
    return;
  }

  return proxyJson(
    res,
    "/api/recon/full",
    {
      method: "POST",
      body: { domain },
      timeout: 240000,
    }
  );
});

module.exports = router;
