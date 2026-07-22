const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../config/db");
const config = require("../config");
const authenticate = require("../middleware/auth");

const router = express.Router();

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
    },
    config.jwtSecret,
    {
      expiresIn: "24h",
    }
  );
}

router.post("/register", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const username = String(req.body.username || "")
      .trim();

    const password = String(req.body.password || "");

    if (!email || !username || !password) {
      return res.status(400).json({
        error: "Email, username and password are required",
      });
    }

    if (!email.includes("@")) {
      return res.status(400).json({
        error: "Enter a valid email address",
      });
    }

    if (username.length < 3) {
      return res.status(400).json({
        error: "Username must contain at least 3 characters",
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must contain at least 8 characters",
      });
    }

    const existing = await db.query(
      `
      SELECT id
      FROM users
      WHERE LOWER(email) = LOWER($1)
         OR LOWER(username) = LOWER($2)
      `,
      [email, username]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: "An account with this email or username already exists",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await db.query(
      `
      INSERT INTO users (
        email,
        username,
        password_hash
      )
      VALUES ($1, $2, $3)
      RETURNING id, email, username, role, created_at
      `,
      [email, username, passwordHash]
    );

    const user = result.rows[0];
    const token = createToken(user);

    return res.status(201).json({
      user,
      token,
    });
  } catch (error) {
    console.error("[AUTH REGISTER ERROR]", error);

    if (error.code === "23505") {
      return res.status(409).json({
        error: "User already exists",
      });
    }

    return res.status(500).json({
      error: "Registration failed",
    });
  }
});

router.post("/login", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required",
      });
    }

    const result = await db.query(
      `
      SELECT
        id,
        email,
        username,
        password_hash,
        role,
        created_at
      FROM users
      WHERE LOWER(email) = LOWER($1)
      `,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Invalid email or password",
      });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return res.status(401).json({
        error: "Invalid email or password",
      });
    }

    const token = createToken(user);

    return res.json({
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        role: user.role,
        created_at: user.created_at,
      },
      token,
    });
  } catch (error) {
    console.error("[AUTH LOGIN ERROR]", error);

    return res.status(500).json({
      error: "Login failed",
    });
  }
});

router.get("/me", authenticate, async (req, res) => {
  try {
    const result = await db.query(
      `
      SELECT
        id,
        email,
        username,
        role,
        created_at
      FROM users
      WHERE id = $1
      `,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "User not found",
      });
    }

    return res.json(result.rows[0]);
  } catch (error) {
    console.error("[AUTH ME ERROR]", error);

    return res.status(500).json({
      error: "Unable to retrieve account",
    });
  }
});

module.exports = router;
