const express = require("express");
const authenticate = require("../middleware/auth");
const { proxyJson } = require("../utils/detectionProxy");

const router = express.Router();

router.post("/lookup", authenticate, async (req, res) => {
  return proxyJson(
    res,
    "/api/shodan/lookup",
    {
      method: "POST",
      body: req.body,
    }
  );
});

module.exports = router;
