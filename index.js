const express = require("express");
const speakeasy = require("speakeasy");

const db = require("./database");

const app = express();
const port = 3000;

app.use(express.json());

app.get("/api", (req, res) => {
  res.json({
    msg: "Welcome to 2fa-speakeasy",
  });
});

app.post("/register", (req, res) => {
  var errors = [];
  if (!req.body.username) {
    errors.push("No username specified");
  }
  if (!req.body.password) {
    errors.push("No password specified");
  }
  if (errors.length) {
    res.status(400).json({
      error: [...errors],
    });
  }
  // Generate secure key
  var secret = speakeasy.generateSecret();

  var insert = "INSERT INTO users (username, password, secret) VALUES (?,?,?)";
  var params = [req.body.username, req.body.password, secret.base32];
  db.run(insert, params, (err, row) => {
    if (err) {
      res.status(400).json({ error: "Username already exists" });
      return;
    }
    res.status(200).json({
      secret: secret.base32,
      otpauth_url: secret.otpauth_url,
    });
  });
});

app.post("/login", (req, res) => {
  var errors = [];
  if (!req.body.username) {
    errors.push("No username specified");
  }
  if (!req.body.password) {
    errors.push("No password specified");
  }
  if (!req.body.otp) {
    errors.push("No otp specified");
  }
  if (errors.length) {
    res.status(400).json({
      error: [...errors],
    });
  }
  // fetch the user from the database
  var sql = "SELECT * FROM users WHERE username = ? AND password = ?";
  var params = [req.body.username, req.body.password];
  db.get(sql, params, (err, row) => {
    if (err) {
      res.status(400).json({ error: err.message });
      return;
    }
    if (!row) {
      res.status(200).json({ error: "User was not found" });
      return;
    }
    var verified = speakeasy.totp.verify({
      secret: row.secret,
      encoding: "base32",
      token: req.body.otp,
    });
    res.json({
      verified: verified,
    });
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
