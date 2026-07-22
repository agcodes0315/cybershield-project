const express = require("express");
const authenticate = require("../middleware/auth");
const { proxyJson } = require("../utils/detectionProxy");

const router = express.Router();

router.get("/campaigns", authenticate, async (req, res) => {
  return proxyJson(
    res,
    "/api/gophish/campaigns"
  );
});

router.get("/campaigns/:id", authenticate, async (req, res) => {
  return proxyJson(
    res,
    `/api/gophish/campaigns/${encodeURIComponent(req.params.id)}`
  );
});

router.get("/pages", authenticate, async (req, res) => {
  return proxyJson(
    res,
    "/api/gophish/pages"
  );
});

router.get("/templates", authenticate, async (req, res) => {
  return proxyJson(
    res,
    "/api/gophish/templates"
  );
});

router.post("/analyze-url", authenticate, async (req, res) => {
  return proxyJson(
    res,
    "/api/gophish/analyze-url",
    {
      method: "POST",
      body: req.body,
    }
  );
});

module.exports = router;
