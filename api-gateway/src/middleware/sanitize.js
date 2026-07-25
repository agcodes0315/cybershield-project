"use strict";

function sanitizeString(value) {
  if (typeof value !== "string") {
    return value;
  }

  return value
    .replace(/[<>]/g, "")
    .replace(/javascript:/gi, "")
    .replace(/on\w+\s*=/gi, "")
    .replace(/eval\s*\(/gi, "")
    .replace(/expression\s*\(/gi, "")
    .trim();
}

function sanitizeValue(value) {
  if (typeof value === "string") {
    return sanitizeString(value);
  }

  if (Array.isArray(value)) {
    return value.map(sanitizeValue);
  }

  if (
    value &&
    typeof value === "object"
  ) {
    for (const key of Object.keys(value)) {
      value[key] =
        sanitizeValue(value[key]);
    }
  }

  return value;
}

function sanitizeMiddleware(
  req,
  res,
  next,
) {
  try {
    if (
      req.body &&
      typeof req.body === "object"
    ) {
      sanitizeValue(req.body);
    }

    /*
     * Do not mutate req.query in Express 5.
     * Express 5 may expose req.query using a getter.
     */

    return next();
  } catch (error) {
    console.error(
      "[SANITIZE ERROR]",
      error,
    );

    return res.status(400).json({
      error: "Invalid request data",
    });
  }
}

module.exports = {
  sanitizeMiddleware,
  sanitizeString,
  sanitizeValue,
};