// Vulnerable Node.js demo - EXPANDED with harder cases.
// Every block below is a real vulnerability class. Some are simple one-line
// patterns; others hide the bug behind helper functions and data flow, to
// test how well Semgrep tracks tainted input. Comments mark the difficulty.
// Nothing here is real or safe. Do not run it.

const express = require("express");
const { exec, execSync } = require("child_process");
const fs = require("fs");
const crypto = require("crypto");
const http = require("http");
const jwt = require("jsonwebtoken");
const app = express();
app.use(express.json());

// ---------------------------------------------------------------------------
// 1. COMMAND INJECTION hidden behind TWO helper functions (needs dataflow).
//    Tainted input travels: route -> buildCmd() -> runner() -> execSync().
//    This is the HARD one. A simple pattern matcher sees execSync(cmd) and
//    cannot tell cmd came from the user. Real taint tracking can.
// ---------------------------------------------------------------------------
function runner(cmd) {
  return execSync(cmd).toString();
}
function buildCmd(host) {
  return "nslookup " + host;
}
app.get("/lookup", (req, res) => {
  const host = req.query.host;   // attacker controlled
  const cmd = buildCmd(host);    // passes through a builder
  res.send(runner(cmd));         // ...and a runner before execSync
});

// ---------------------------------------------------------------------------
// 2. PATH TRAVERSAL - file read with user input (../../etc/passwd).
// ---------------------------------------------------------------------------
app.get("/download", (req, res) => {
  const file = req.query.name;
  const data = fs.readFileSync("/var/data/" + file);
  res.send(data);
});

// ---------------------------------------------------------------------------
// 3. SSRF - the server fetches a URL the user controls.
// ---------------------------------------------------------------------------
app.get("/fetch", (req, res) => {
  http.get(req.query.url, (r) => {
    r.pipe(res);
  });
});

// ---------------------------------------------------------------------------
// 4. NoSQL injection - raw request body straight into a Mongo query.
//    {"$ne": null} in the password field bypasses the check.
// ---------------------------------------------------------------------------
app.post("/login", (req, res) => {
  db.collection("users").findOne({
    username: req.body.username,
    password: req.body.password,
  });
});

// ---------------------------------------------------------------------------
// 5. WEAK CRYPTO - MD5 used to hash passwords.
// ---------------------------------------------------------------------------
function hashPassword(pw) {
  return crypto.createHash("md5").update(pw).digest("hex");
}

// ---------------------------------------------------------------------------
// 6. INSECURE RANDOMNESS - Math.random used to make a security token.
// ---------------------------------------------------------------------------
function makeToken() {
  return Math.random().toString(36).slice(2);
}

// ---------------------------------------------------------------------------
// 7. HARDCODED SECRET used to sign JWTs.
// ---------------------------------------------------------------------------
const JWT_SECRET = "s3cr3t-signing-key-do-not-commit";
function sign(user) {
  return jwt.sign({ user }, JWT_SECRET);
}

// ---------------------------------------------------------------------------
// 8. OPEN REDIRECT - redirect target is user controlled.
// ---------------------------------------------------------------------------
app.get("/go", (req, res) => {
  res.redirect(req.query.next);
});

// ---------------------------------------------------------------------------
// 9. INSECURE DESERIALIZATION via the Function constructor (eval cousin).
// ---------------------------------------------------------------------------
app.post("/run", (req, res) => {
  const fn = new Function("return " + req.body.code);
  res.send(String(fn()));
});

// ---------------------------------------------------------------------------
// 10. REFLECTED XSS - user input written straight into the HTML response.
// ---------------------------------------------------------------------------
app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

// ---------------------------------------------------------------------------
// 11. CLASSIC eval (simple one-line pattern, easy baseline).
// ---------------------------------------------------------------------------
app.get("/calc", (req, res) => {
  res.send(String(eval(req.query.expr)));
});

// ---------------------------------------------------------------------------
// 12. SQL INJECTION by string concatenation.
// ---------------------------------------------------------------------------
app.get("/user", (req, res) => {
  const query = "SELECT * FROM users WHERE id = '" + req.query.id + "'";
  db.query(query, (err, rows) => {
    res.json(rows);
  });
});

app.listen(3000);
