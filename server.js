require("dotenv").config();
const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const Razorpay = require("razorpay");

const app = express();

// Temporary serverless-safe store.
// This removes local SQLite, which cannot be used as persistent storage on Vercel.
// We will replace this with Supabase/Postgres before production launch.
const users = new Map();
let nextUserId = 1;

// Razorpay webhook MUST receive the raw request body.
app.post(
  "/api/razorpay-webhook",
  express.raw({ type: "application/json" }),
  (req, res) => {
    try {
      const signature = req.get("X-Razorpay-Signature");
      const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
      if (!secret) return res.status(500).send("Webhook secret not configured");

      const expected = crypto
        .createHmac("sha256", secret)
        .update(req.body)
        .digest("hex");

      if (
        !signature ||
        !crypto.timingSafeEqual(
          Buffer.from(expected),
          Buffer.from(signature)
        )
      ) {
        return res.status(400).send("Invalid signature");
      }

      const event = JSON.parse(req.body.toString("utf8"));
      const entity = event.payload?.subscription?.entity;

      if (entity?.id) {
        for (const user of users.values()) {
          if (user.subscription_id === entity.id) {
            user.subscription_status = entity.status;
            user.plan = ["active", "authenticated"].includes(entity.status)
              ? "pro"
              : "free";
          }
        }
      }

      return res.sendStatus(200);
    } catch (e) {
      console.error("Webhook error", e);
      return res.sendStatus(400);
    }
  }
);

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const JWT_SECRET = process.env.JWT_SECRET || "dev-only-change-me";

const rp =
  process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET
    ? new Razorpay({
        key_id: process.env.RAZORPAY_KEY_ID,
        key_secret: process.env.RAZORPAY_KEY_SECRET,
      })
    : null;

function auth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Login required" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Session expired" });
  }
}

function tokenFor(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

app.post("/api/signup", async (req, res) => {
  const { email, password } = req.body || {};

  if (
    !email ||
    !password ||
    password.length < 8
  ) {
    return res.status(400).json({
      error: "Enter a valid email and password of at least 8 characters.",
    });
  }

  const clean = email.toLowerCase().trim();

  if (users.has(clean)) {
    return res.status(409).json({
      error: "That email is already registered.",
    });
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    const user = {
      id: nextUserId++,
      email: clean,
      password_hash: hash,
      plan: "free",
      subscription_id: null,
      subscription_status: "inactive",
      created_at: new Date().toISOString(),
    };

    users.set(clean, user);

    res.cookie("token", tokenFor(user), {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 864e5,
    });

    return res.json({
      ok: true,
      user: { id: user.id, email: user.email },
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Could not create account." });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  const user = users.get((email || "").toLowerCase().trim());

  if (
    !user ||
    !(await bcrypt.compare(password || "", user.password_hash))
  ) {
    return res.status(401).json({
      error: "Invalid email or password.",
    });
  }

  res.cookie("token", tokenFor(user), {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 864e5,
  });

  return res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ ok: true });
});

app.get("/api/me", auth, (req, res) => {
  const user = [...users.values()].find(
    (u) => u.id === req.user.id
  );

  if (!user) return res.status(401).json({ error: "Account not found" });

  return res.json({
    id: user.id,
    email: user.email,
    plan: user.plan,
    subscription_id: user.subscription_id,
    subscription_status: user.subscription_status,
    created_at: user.created_at,
  });
});

app.post("/api/create-subscription", auth, async (req, res) => {
  if (!rp) {
    return res.status(503).json({
      error:
        "Razorpay is not configured. Check RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET.",
    });
  }

  if (!process.env.RAZORPAY_PLAN_ID) {
    return res.status(503).json({
      error: "Razorpay plan ID is missing.",
    });
  }

  const user = [...users.values()].find(
    (u) => u.id === req.user.id
  );

  if (!user) return res.status(401).json({ error: "Account not found" });

  try {
    if (
      user.subscription_id &&
      ["created", "authenticated", "active", "pending"].includes(
        user.subscription_status
      )
    ) {
      return res.json({
        subscriptionId: user.subscription_id,
        keyId: process.env.RAZORPAY_KEY_ID,
        reused: true,
      });
    }

    const sub = await rp.subscriptions.create({
      plan_id: process.env.RAZORPAY_PLAN_ID,
      total_count: 1200,
      quantity: 1,
      customer_notify: 1,
      notes: {
        creatorai_user_id: String(user.id),
        email: user.email,
      },
    });

    user.subscription_id = sub.id;
    user.subscription_status = sub.status;

    return res.json({
      subscriptionId: sub.id,
      keyId: process.env.RAZORPAY_KEY_ID,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({
      error:
        e.error?.description ||
        e.message ||
        "Could not create subscription.",
    });
  }
});

app.post("/api/verify-subscription", auth, (req, res) => {
  const {
    razorpay_payment_id,
    razorpay_subscription_id,
    razorpay_signature,
  } = req.body || {};

  if (
    !razorpay_payment_id ||
    !razorpay_subscription_id ||
    !razorpay_signature
  ) {
    return res.status(400).json({
      error: "Missing Razorpay verification fields.",
    });
  }

  const user = [...users.values()].find(
    (u) => u.id === req.user.id
  );

  if (
    !user ||
    user.subscription_id !== razorpay_subscription_id
  ) {
    return res.status(400).json({
      error: "Subscription does not belong to this account.",
    });
  }

  const body =
    `${razorpay_payment_id}|${razorpay_subscription_id}`;

  const expected = crypto
    .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
    .update(body)
    .digest("hex");

  if (
    !crypto.timingSafeEqual(
      Buffer.from(expected),
      Buffer.from(razorpay_signature)
    )
  ) {
    return res.status(400).json({
      error: "Payment verification failed.",
    });
  }

  user.plan = "pro";
  user.subscription_status = "authenticated";

  return res.json({
    ok: true,
    plan: "pro",
    subscription_status: "authenticated",
  });
});

app.post("/api/generate", auth, (req, res) => {
  const user = [...users.values()].find(
    (u) => u.id === req.user.id
  );

  if (!user || user.plan !== "pro") {
    return res.status(403).json({
      error: "Creator Pro is required. Upgrade for ₹199/month.",
    });
  }

  const { prompt, type = "video" } = req.body || {};

  if (!prompt || prompt.length < 5) {
    return res.status(400).json({
      error: "Enter a prompt.",
    });
  }

  return res.json({
    ok: true,
    status: "queued",
    type,
    prompt,
    message:
      "CreatorAI generation endpoint is ready. Connect an AI video/image/voice provider to return the finished media.",
  });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

module.exports = app;

if (require.main === module) {
  app.listen(process.env.PORT || 3000, () =>
    console.log(
      `CreatorAI running on http://localhost:${process.env.PORT || 3000}`
    )
  );
}
