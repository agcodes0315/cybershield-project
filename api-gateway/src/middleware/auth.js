"use strict";

const jwt = require("jsonwebtoken");
const config = require("../config");

function authenticate(req, res, next) {
  const authHeader =
    req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      error: "Unauthorized: No token provided",
      code: "TOKEN_MISSING",
    });
  }

  const [scheme, token] =
    authHeader.split(" ");

  if (
    scheme?.toLowerCase() !== "bearer" ||
    !token
  ) {
    return res.status(401).json({
      error:
        "Unauthorized: Authorization header must use Bearer token",
      code: "INVALID_AUTH_HEADER",
    });
  }

  if (!config.jwtSecret) {
    console.error(
      "[AUTH ERROR] JWT_SECRET is not configured.",
    );

    return res.status(500).json({
      error:
        "Authentication service is not configured",
      code: "JWT_SECRET_MISSING",
    });
  }

  try {
    const decoded = jwt.verify(
      token.trim(),
      config.jwtSecret,
      {
        algorithms: ["HS256"],
      },
    );

    req.user = decoded;

    return next();
  } catch (error) {
    console.error(
      "[AUTH ERROR]",
      error.name,
      error.message,
    );

    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        error:
          "Unauthorized: Token has expired",
        code: "TOKEN_EXPIRED",
      });
    }

    return res.status(401).json({
      error:
        "Unauthorized: Invalid token",
      code: "TOKEN_INVALID",
    });
  }
}

function authorize(...allowedRoles) {
  return function authorizeRole(
    req,
    res,
    next,
  ) {
    if (!req.user) {
      return res.status(401).json({
        error: "Authentication required",
        code: "AUTHENTICATION_REQUIRED",
      });
    }

    if (
      allowedRoles.length > 0 &&
      !allowedRoles.includes(req.user.role)
    ) {
      return res.status(403).json({
        error: "Insufficient permissions",
        code: "INSUFFICIENT_PERMISSIONS",
      });
    }

    return next();
  };
}

module.exports = authenticate;
module.exports.authenticate = authenticate;
module.exports.authorize = authorize;