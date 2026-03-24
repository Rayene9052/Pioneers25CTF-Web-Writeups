const path = require("path");
const express = require("express");
const session = require("express-session");
const { MongoClient } = require("mongodb");
const rateLimit = require("express-rate-limit");

const app = express();

const PORT = process.env.PORT || 8080;
const MONGO_URL = process.env.MONGO_URL || "mongodb://127.0.0.1:27017";
const DB_NAME = process.env.DB_NAME || "ctf";

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Y0U_H4v3_n0_3n3m1es";
const FLAG = process.env.FLAG || "Pioneers25{dummy_flag}";
const SESSION_SECRET = process.env.SESSION_SECRET || "change_me";

// Needed for password[$regex] to become an object:
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax" }
  })
);
// ----------------------------
// Infrastructure rate limiting
// ----------------------------

// 25 requests per second for login
const loginLimiter = rateLimit({
  windowMs: 1000,
  max: 25,
  standardHeaders: false,
  legacyHeaders: false,
  message: "Too many requests"
});

const searchLimiter = rateLimit({
  windowMs: 1000,
  max: 400, // was 40 — allow brute-force without random failure
  standardHeaders: false,
  legacyHeaders: false,
  handler: (req, res) => {
    // Keep blind behavior even when throttled
    return res.status(200).send("NOT FOUND");
  }
});

app.post("/login", loginLimiter);
app.get("/admin/search", searchLimiter);

// Static assets (CSS)
app.use("/static", express.static(path.join(__dirname, "public")));

function invalid(res) {
  // Keep it simple + consistent
  return res.status(200).send("Invalid credentials");
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.user === "admin") return next();
  return res.status(403).send("Forbidden");
}

let db;

async function main() {
  const client = new MongoClient(MONGO_URL);
  await client.connect();
  db = client.db(DB_NAME);
    // Ensure values match ENV every boot (stable even without wiping volumes)
  await db.collection("reports").updateOne(
    { title: "Internal Flag Report" },
    { $set: { content: FLAG, visibility: "internal" } },
    { upsert: true }
  );

  await db.collection("users").updateOne(
    { username: "admin" },
    { $set: { username: "admin", role: "admin", password: ADMIN_PASSWORD } },
    { upsert: true }
  );

  app.get("/", (req, res) => res.redirect("/login"));
  app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "views/login.html")));

  app.get("/admin", requireAdmin, (req, res) => res.redirect("/admin/dashboard"));
  app.get("/admin/dashboard", requireAdmin, (req, res) =>
    res.sendFile(path.join(__dirname, "views/admin.html"))
  );
  app.get("/admin/search-ui", requireAdmin, (req, res) =>
    res.sendFile(path.join(__dirname, "views/search.html"))
  );
// ----------------------------
// Stage 1: Blind regex login (CORRECT FIX)
// ----------------------------
app.post("/login", async (req, res) => {
  try {
    if (req.body.username !== "admin") return invalid(res);

    let pw = req.body.password;

    if (pw && typeof pw === "object") {
      const keys = Object.keys(pw);
      if (keys.length !== 1 || keys[0] !== "$regex") return invalid(res);
      if (typeof pw.$regex !== "string") return invalid(res);

      const userInput = pw.$regex;

      // Only allow prefix patterns starting with ^
      if (!userInput.startsWith("^")) return invalid(res);

      // 🔒 Prevent infinite $$$ abuse
      if (userInput.includes("$")) return invalid(res);

      // Keep regex as-is (prefix match)
      pw = { $regex: userInput };
    } else if (typeof pw !== "string") {
      return invalid(res);
    }

    const user = await db.collection("users").findOne({
      username: "admin",
      role: "admin",
      password: pw
    });

    if (!user) return invalid(res);

    req.session.user = "admin";
    return res.redirect("/admin/dashboard");
  } catch (e) {
    return invalid(res);
  }
});
  // ----------------------------
  // Stage 2: Authenticated blind extraction
  // /admin/search?title=Internal%20Flag%20Report&content[$regex]=^P
  // Returns: FOUND / NOT FOUND
  // ----------------------------
  // ----------------------------
// Stage 2: Authenticated blind extraction (HARDENED)
// ----------------------------
app.get("/admin/search", requireAdmin, async (req, res) => {
  try {
    const title =
      typeof req.query.title === "string"
        ? req.query.title
        : "Internal Flag Report";

    let content = req.query.content;

    // Allow only exact string OR {$regex: "..."}
    if (content && typeof content === "object") {
      const keys = Object.keys(content);

      // Only allow $regex operator
      if (keys.length !== 1 || keys[0] !== "$regex") {
        return res.status(200).send("NOT FOUND");
      }

      if (typeof content.$regex !== "string") {
        return res.status(200).send("NOT FOUND");
      }

      const userInput = content.$regex;

      // Only allow prefix-style patterns
      if (!userInput.startsWith("^")) {
        return res.status(200).send("NOT FOUND");
      }

      // Prevent abuse like infinite $$$
      if (userInput.includes("$")) {
        return res.status(200).send("NOT FOUND");
      }

      content = { $regex: userInput };
    } else if (content !== undefined && typeof content !== "string") {
      return res.status(200).send("NOT FOUND");
    }

    const query = { title };
    if (content !== undefined) query.content = content;

    const found = await db
      .collection("reports")
      .findOne(query, { projection: { _id: 1 } });

    // Optional tiny delay (anti-burst smoothing)
    await new Promise((r) => setTimeout(r, 10));

    return res.status(200).send(found ? "FOUND" : "NOT FOUND");
  } catch (e) {
    // Always uniform response
    await new Promise((r) => setTimeout(r, 10));
    return res.status(200).send("NOT FOUND");
  }
});
  app.post("/logout", (req, res) => {
    req.session.destroy(() => res.redirect("/login"));
  });

  app.get("/health", (_, res) => res.status(200).send("ok"));

  app.listen(PORT, () => console.log(`CTF web up on :${PORT}`));
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});