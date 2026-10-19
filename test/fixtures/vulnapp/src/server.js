const express = require("express");
const path = require("path");
const db = require("./db");

const app = express();
const UPLOADS = path.join(__dirname, "..", "uploads");

app.get("/users", async (req, res) => {
  const name = req.query.name;
  const rows = await db.query("SELECT id, email FROM users WHERE name = '" + name + "'");
  res.json(rows);
});

app.get("/files/:name", (req, res) => {
  const file = path.join(UPLOADS, req.params.name);
  res.sendFile(file);
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

module.exports = app;
