// Vulnerable Node.js demo - COMPLEX edition.
// This mimics real production code: classes, async/await, Express middleware,
// data passed through objects/arrays, and a sanitizer that does NOT actually
// sanitize. The bugs are hidden behind layers on purpose, to test whether the
// scanner can follow tainted input through indirection, not just one-liners.
// Nothing here is safe. Do not run it.

const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const app = express();
app.use(express.json());

// ---------------------------------------------------------------------------
// A "sanitizer" that looks protective but only trims whitespace. Tainted data
// stays tainted after this. Tests whether the scanner is fooled by the name.
// ---------------------------------------------------------------------------
function sanitize(input) {
  return String(input).trim();
}

// Generic deep-merge helper (classic prototype-pollution sink).
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// ---------------------------------------------------------------------------
// 1. MIDDLEWARE TAINT. User input is stashed on the request object here, then
//    consumed by a handler much later. The taint crosses functions via req.
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  req.ctx = { rawPath: req.query.path, rawHost: req.query.host };
  next();
});

// ---------------------------------------------------------------------------
// A service class. The dangerous sink (exec) is a private-ish method, reached
// only through a chain: handler -> runDiagnostic -> buildOptions -> execute.
// ---------------------------------------------------------------------------
class OpsService {
  constructor() {
    this.prefix = "ping -c 1 ";
  }

  execute(opts) {
    // Sink. opts.command originates from user input several hops back.
    return new Promise((resolve, reject) => {
      exec(opts.command, (err, stdout) => (err ? reject(err) : resolve(stdout)));
    });
  }

  buildOptions(target) {
    const cleaned = sanitize(target); // looks safe, is not
    return { command: this.prefix + cleaned, timeout: 5000 };
  }

  async runDiagnostic(target) {
    const opts = this.buildOptions(target);
    return this.execute(opts);
  }
}

const ops = new OpsService();

// 2. COMMAND INJECTION through the class chain + a fake sanitizer (hard).
app.get("/diag", async (req, res) => {
  const out = await ops.runDiagnostic(req.ctx.rawHost);
  res.send(out);
});

// 3. PATH TRAVERSAL where the path travels through middleware, an array, and
//    path.join before reaching fs (hard, multi-hop through a data structure).
app.get("/read", (req, res) => {
  const segments = ["/srv/files", req.ctx.rawPath];
  const full = path.join(...segments);
  fs.readFile(full, "utf8", (err, data) => res.send(data));
});

// 4. SSRF behind async/await and a helper.
async function fetchRemote(url) {
  const resp = await axios.get(url);
  return resp.data;
}
app.post("/proxy", async (req, res) => {
  const body = req.body;
  const data = await fetchRemote(body.target); // user-controlled URL
  res.json(data);
});

// 5. INSECURE DESERIALIZATION. JSON parsed, a field pulled out, then run
//    through the Function constructor inside a callback.
app.post("/exec-rule", (req, res) => {
  const parsed = JSON.parse(req.body.rule);
  const handlers = {
    run: (expr) => new Function("ctx", "return " + expr),
  };
  const fn = handlers.run(parsed.expression);
  res.send(String(fn({})));
});

// 6. PROTOTYPE POLLUTION. Raw body deep-merged into an object.
app.post("/config", (req, res) => {
  const config = {};
  merge(config, req.body);
  res.json(config);
});

// 7. DYNAMIC REQUIRE driven by user input (arbitrary module load).
app.get("/plugin", (req, res) => {
  const mod = require(req.query.name);
  res.send(typeof mod);
});

// 8. SQL INJECTION where input passes through the fake sanitizer first, and
//    the query is built with a template literal across two functions.
function buildUserQuery(id) {
  const safeish = sanitize(id);
  return `SELECT * FROM users WHERE id = '${safeish}'`;
}
app.get("/account", (req, res) => {
  const q = buildUserQuery(req.query.id);
  db.query(q, (err, rows) => res.json(rows));
});

// 9. COMMAND INJECTION via template literal, conditional path (only on a flag).
app.get("/log", (req, res) => {
  const branch = req.query.branch || "main";
  if (req.query.verbose) {
    exec(`git log ${branch} --stat`, (e, out) => res.send(out));
  } else {
    res.send("ok");
  }
});

app.listen(3000);
