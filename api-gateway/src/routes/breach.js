const express = require("express");
const authenticate = require("../middleware/auth");
const { proxyJson } = require("../utils/detectionProxy");

const router = express.Router();

router.post("/check-password", authenticate, async (req, res) => {
  return proxyJson(
    res,
    "/api/breach/check-password",
    {
      method: "POST",
      body: req.body,
    }
  );
});

router.post("/check-email", authenticate, async (req, res) => {
  return proxyJson(
    res,
    "/api/breach/check-email",
    {
      method: "POST",
      body: req.body,
    }
  );
});

module.exports = router;
