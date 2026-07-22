const jwt = require("jsonwebtoken");
const config = require("../config");

function authenticate(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Unauthorized: No token provided",
      });
    }

    const token = authHeader.slice(7).trim();

    if (!token) {
      return res.status(401).json({
        error: "Unauthorized: No token provided",
      });
    }

    const decoded = jwt.verify(token, config.jwtSecret);

    req.user = decoded;
    return next();
  } catch (error) {
    console.error("[AUTH ERROR]", error.message);

    return res.status(401).json({
      error: "Unauthorized: Invalid or expired token",
    });
  }
}

function authorize(...allowedRoles) {
  return function authorizeRole(req, res, next) {
    if (!req.user) {
      return res.status(401).json({
        error: "Authentication required",
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: "Insufficient permissions",
      });
    }

    return next();
  };
}

module.exports = authenticate;
module.exports.authenticate = authenticate;
module.exports.authorize = authorize;
