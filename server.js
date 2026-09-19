const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL } = require("url");

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!ADMIN_PASSWORD) {
  console.error("ОШИБКА: задайте переменную ADMIN_PASSWORD перед запуском.");
  console.error('Windows PowerShell: $env:ADMIN_PASSWORD="ваш_пароль"; npm start');
  console.error('Linux/macOS: ADMIN_PASSWORD="ваш_пароль" npm start');
  process.exit(1);
}

const DATA_FILE = path.join(__dirname, "data", "profiles.json");
const PUBLIC_DIR = __dirname;
const sessions = new Set();

function ensureData() {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, "[]", "utf8");
}
function readProfiles() {
  ensureData();
  try {
    const data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}
function writeProfiles(profiles) {
  ensureData();
  fs.writeFileSync(DATA_FILE, JSON.stringify(profiles, null, 2), "utf8");
}
function json(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS"
  });
  res.end(text);
}
function body(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", chunk => {
      raw += chunk;
      if (raw.length > 1_000_000) req.destroy();
    });
    req.on("end", () => {
      try { resolve(raw ? JSON.parse(raw) : {}); }
      catch { reject(new Error("invalid_json")); }
    });
    req.on("error", reject);
  });
}
function adminToken(req) {
  const value = req.headers.authorization || "";
  return value.startsWith("Bearer ") ? value.slice(7) : "";
}
function requireAdmin(req, res) {
  const token = adminToken(req);
  if (!token || !sessions.has(token)) {
    json(res, 401, { ok: false, error: "admin_required" });
    return false;
  }
  return true;
}
function safeProfile(p) {
  return {
    id: String(p.id),
    name: String(p.name || "").slice(0, 80),
    games: Array.isArray(p.games) ? p.games.slice(0, 20).map(g => ({
      game: String(g.game || "").slice(0, 80),
      nick: String(g.nick || "").slice(0, 80)
    })) : [],
    playtime: String(p.playtime || "").slice(0, 500),
    contact: String(p.contact || "").slice(0, 200),
    date: String(p.date || "")
  };
}
function serveStatic(req, res, pathname) {
  let file = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const full = path.normalize(path.join(PUBLIC_DIR, file));
  if (!full.startsWith(PUBLIC_DIR)) {
    res.writeHead(403); return res.end("Forbidden");
  }
  fs.readFile(full, (err, data) => {
    if (err) {
      res.writeHead(404, {"Content-Type":"text/plain; charset=utf-8"});
      return res.end("Not found");
    }
    const ext = path.extname(full);
    const types = {
      ".html":"text/html; charset=utf-8",
      ".css":"text/css; charset=utf-8",
      ".js":"application/javascript; charset=utf-8",
      ".json":"application/json; charset=utf-8",
      ".svg":"image/svg+xml"
    };
    res.writeHead(200, {"Content-Type": types[ext] || "application/octet-stream"});
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS"
    });
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const p = url.pathname;

  try {
    if (p === "/api/health" && req.method === "GET")
      return json(res, 200, {ok:true, service:"ЕСИЧ", time:new Date().toISOString()});

    if (p === "/api/profiles" && req.method === "GET")
      return json(res, 200, {ok:true, profiles:readProfiles()});

    if (p === "/api/profiles" && req.method === "POST") {
      const incoming = await body(req);
      const profile = safeProfile({
        id: incoming.id || crypto.randomUUID(),
        name: incoming.name,
        games: incoming.games,
        playtime: incoming.playtime,
        contact: incoming.contact,
        date: incoming.date || new Date().toLocaleString("ru-RU")
      });
      if (!profile.name || !profile.playtime || !profile.contact || !profile.games.length)
        return json(res, 400, {ok:false,error:"Заполните все поля."});
      const profiles = readProfiles();
      const index = profiles.findIndex(x => x.id === profile.id);
      if (index >= 0) profiles[index] = profile;
      else profiles.push(profile);
      writeProfiles(profiles);
      return json(res, 200, {ok:true, profile});
    }

    if (p === "/api/profiles" && req.method === "DELETE") {
      if (!requireAdmin(req,res)) return;
      writeProfiles([]);
      return json(res, 200, {ok:true});
    }

    if (p.startsWith("/api/profiles/") && req.method === "DELETE") {
      if (!requireAdmin(req,res)) return;
      const id = decodeURIComponent(p.slice("/api/profiles/".length));
      const profiles = readProfiles();
      const next = profiles.filter(x => x.id !== id);
      writeProfiles(next);
      return json(res, 200, {ok:true, deleted:profiles.length-next.length});
    }

    if (p === "/api/admin/login" && req.method === "POST") {
      const incoming = await body(req);
      if (String(incoming.password || "") !== ADMIN_PASSWORD)
        return json(res, 401, {ok:false,error:"Неверный пароль."});
      const token = crypto.randomBytes(32).toString("hex");
      sessions.add(token);
      return json(res, 200, {ok:true, token});
    }

    if (p === "/api/admin/logout" && req.method === "POST") {
      const token = adminToken(req);
      if (token) sessions.delete(token);
      return json(res, 200, {ok:true});
    }

    if (p === "/api/admin/status" && req.method === "GET") {
      if (!requireAdmin(req,res)) return;
      return json(res, 200, {ok:true, profiles:readProfiles().length});
    }

    return serveStatic(req,res,p);
  } catch (e) {
    console.error(e);
    return json(res, 500, {ok:false,error:"Ошибка сервера."});
  }
});

server.listen(PORT, HOST, () => {
  console.log(`ЕСИЧ запущен: http://localhost:${PORT}`);
});
