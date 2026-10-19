const { Pool } = require("pg");

const pool = new Pool();

async function query(sql, params) {
  const result = await pool.query(sql, params);
  return result.rows;
}

module.exports = { query };
