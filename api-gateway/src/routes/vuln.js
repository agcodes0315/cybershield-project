const express = require("express");
const authenticate = require("../middleware/auth");
const { proxyJson } = require("../utils/detectionProxy");

const router = express.Router();

router.post("/headers", authenticate, async (req, res) => {
  return proxyJson(
    res,
    "/api/vuln/headers",
    {
      method: "POST",
      body: req.body,
    }
  );
});

router.post("/full", authenticate, async (req, res) => {
  return proxyJson(
    res,
    "/api/vuln/full",
    {
      method: "POST",
      body: req.body,
      timeout: 240000,
    }
  );
});

router.post("/nikto", authenticate, async (req, res) => {
  return proxyJson(
    res,
    "/api/vuln/nikto",
    {
      method: "POST",
      body: req.body,
      timeout: 240000,
    }
  );
});

router.post("/capture", authenticate, async (req, res) => {
  return proxyJson(
    res,
    "/api/vuln/capture",
    {
      method: "POST",
      body: req.body,
      timeout: 240000,
    }
  );
});

module.exports = router;
