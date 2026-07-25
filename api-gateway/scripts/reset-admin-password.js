"use strict";

const bcrypt = require("bcryptjs");
const db = require("../src/config/db");

async function resetAdminPassword() {
  const email = String(
    process.env.ADMIN_EMAIL || "",
  )
    .trim()
    .toLowerCase();

  const newPassword = String(
    process.env.ADMIN_NEW_PASSWORD || "",
  );

  if (!email) {
    throw new Error(
      "ADMIN_EMAIL environment variable is required.",
    );
  }

  if (!email.includes("@")) {
    throw new Error(
      "ADMIN_EMAIL must be a valid email address.",
    );
  }

  if (!newPassword) {
    throw new Error(
      "ADMIN_NEW_PASSWORD environment variable is required.",
    );
  }

  if (newPassword.length < 12) {
    throw new Error(
      "The new password must contain at least 12 characters.",
    );
  }

  const existingUser = await db.query(
    `
    SELECT
      id,
      email,
      username,
      role
    FROM users
    WHERE LOWER(email) = LOWER($1)
    LIMIT 1
    `,
    [email],
  );

  if (existingUser.rows.length === 0) {
    throw new Error(
      `No user was found with email: ${email}`,
    );
  }

  const passwordHash = await bcrypt.hash(
    newPassword,
    12,
  );

  const result = await db.query(
    `
    UPDATE users
    SET
      password_hash = $1,
      role = 'admin'
    WHERE LOWER(email) = LOWER($2)
    RETURNING
      id,
      email,
      username,
      role,
      created_at
    `,
    [passwordHash, email],
  );

  const updatedUser = result.rows[0];

  console.log("");
  console.log("========================================");
  console.log(" CyberShield admin account recovered");
  console.log("========================================");
  console.log(`User ID:  ${updatedUser.id}`);
  console.log(`Username: ${updatedUser.username}`);
  console.log(`Email:    ${updatedUser.email}`);
  console.log(`Role:     ${updatedUser.role}`);
  console.log("");
  console.log(
    "The password was updated successfully.",
  );
  console.log(
    "For security, the password has not been printed.",
  );
}

resetAdminPassword()
  .catch((error) => {
    console.error("");
    console.error(
      "[ADMIN RESET FAILED]",
      error.message,
    );

    process.exitCode = 1;
  })
  .finally(async () => {
    try {
      if (
        db &&
        typeof db.end === "function"
      ) {
        await db.end();
      }
    } catch (error) {
      console.error(
        "[DATABASE CLOSE ERROR]",
        error.message,
      );
    }
  });