const { Pool } = require("pg");
const config = require("./index");

const pool = new Pool({
  host: config.db.host,
  port: config.db.port,
  database: config.db.name,
  user: config.db.user,
  password: config.db.password,

  ssl: config.db.ssl
    ? {
        rejectUnauthorized: false,
      }
    : false,

  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 15000,
});

pool.on("connect", () => {
  console.log("[DB] Connected to PostgreSQL");
});

pool.on("error", (error) => {
  console.error("[DB] Unexpected pool error:", error);
});

async function testConnection() {
  const result = await pool.query("SELECT NOW() AS current_time");
  return result.rows[0];
}

module.exports = {
  query: (text, params) => pool.query(text, params),
  testConnection,
  pool,
};
