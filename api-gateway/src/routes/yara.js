const express = require("express");
const authenticate = require("../middleware/auth");
const { proxyJson } = require("../utils/detectionProxy");

const router = express.Router();

router.post("/scan", authenticate, async (req, res) => {
  return proxyJson(
    res,
    "/api/yara/scan",
    {
      method: "POST",
      body: req.body,
      timeout: 180000,
    }
  );
});

router.get("/rules", authenticate, async (req, res) => {
  return proxyJson(
    res,
    "/api/yara/rules"
  );
});

module.exports = router;
