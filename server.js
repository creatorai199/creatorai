require("dotenv").config();

const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const Razorpay = require("razorpay");
const { createClient } = require("@supabase/supabase-js");

const app = express();

/* =========================
   SUPABASE
========================= */

const supabase =
  process.env.SUPABASE_URL && process.env.SUPABASE_SECRET_KEY
    ? createClient(
        process.env.SUPABASE_URL,
        process.env.SUPABASE_SECRET_KEY
      )
    : null;

/* =========================
   RAZORPAY WEBHOOK
   MUST RECEIVE RAW BODY
========================= */

app.post(
  "/api/razorpay-webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const signature = req.get("X-Razorpay-Signature");
      const secret = process.env.RAZORPAY_WEBHOOK_SECRET;

      if (!secret) {
        return res.status(500).send("Webhook secret not configured");
      }

      const expected = crypto
        .createHmac("sha256", secret)
        .update(req.body)
        .digest("hex");

      if (
        !signature ||
        signature.length !== expected.length ||
        !crypto.timingSafeEqual(
          Buffer.from(expected),
          Buffer.from(signature)
        )
      ) {
        return res.status(400).send("Invalid signature");
      }

      const event = JSON.parse(req.body.toString("utf8"));
      const entity = event.payload?.subscription?.entity;

      if (entity?.id && supabase) {
        const newPlan = ["active", "authenticated"].includes(entity.status)
          ? "pro"
          : "free";

        const { error } = await supabase
          .from("users")
          .update({
            subscription_status: entity.status,
            plan: newPlan,
          })
          .eq("subscription_id", entity.id);

        if (error) {
          console.error("Supabase webhook update error:", error);
          return res.sendStatus(500);
        }
      }

      return res.sendStatus(200);
    } catch (e) {
      console.error("Webhook error:", e);
      return res.sendStatus(400);
    }
  }
);

/* =========================
   APP MIDDLEWARE
========================= */

app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const JWT_SECRET = process.env.JWT_SECRET || "dev-only-change-me";

/* =========================
   RAZORPAY
========================= */

const rp =
  process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET
    ? new Razorpay({
        key_id: process.env.RAZORPAY_KEY_ID,
        key_secret: process.env.RAZORPAY_KEY_SECRET,
      })
    : null;

/* =========================
   AUTH
========================= */

function auth(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({
      error: "Login required",
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: "Session expired",
    });
  }
}

function tokenFor(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
    },
    JWT_SECRET,
    {
      expiresIn: "7d",
    }
  );
}

/* =========================
   GET USER
========================= */

async function getUserById(id) {
  if (!supabase) {
    throw new Error("Supabase is not configured.");
  }

  const { data, error } = await supabase
    .from("users")
    .select("*")
    .eq("id", id)
    .maybeSingle();

  if (error) {
    console.error("Supabase get user error:", error);
    throw error;
  }

  return data;
}

/* =========================
   SIGNUP
========================= */

app.post("/api/signup", async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password || password.length < 8) {
    return res.status(400).json({
      error:
        "Enter a valid email and password of at least 8 characters.",
    });
  }

  if (!supabase) {
    return res.status(503).json({
      error: "Database is not configured.",
    });
  }

  const clean = email.toLowerCase().trim();

  try {
    const { data: existingUser, error: lookupError } = await supabase
      .from("users")
      .select("id")
      .eq("email", clean)
      .maybeSingle();

    if (lookupError) {
      console.error("Signup lookup error:", lookupError);
      return res.status(500).json({
        error: "Could not check account.",
      });
    }

    if (existingUser) {
      return res.status(409).json({
        error: "That email is already registered.",
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const { data: user, error } = await supabase
      .from("users")
      .insert({
        email: clean,
        password_hash: hash,
        plan: "free",
        subscription_id: null,
        subscription_status: "inactive",
      })
      .select("*")
      .single();

    if (error) {
      console.error("Signup insert error:", error);

      if (error.code === "23505") {
        return res.status(409).json({
          error: "That email is already registered.",
        });
      }

      return res.status(500).json({
        error: "Could not create account.",
      });
    }

    res.cookie("token", tokenFor(user), {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 864e5,
    });

    return res.json({
      ok: true,
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch (e) {
    console.error("Signup error:", e);

    return res.status(500).json({
      error: "Could not create account.",
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};

  if (!supabase) {
    return res.status(503).json({
      error: "Database is not configured.",
    });
  }

  try {
    const clean = (email || "").toLowerCase().trim();

    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", clean)
      .maybeSingle();

    if (error) {
      console.error("Login lookup error:", error);

      return res.status(500).json({
        error: "Could not login right now.",
      });
    }

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

    return res.json({
      ok: true,
    });
  } catch (e) {
    console.error("Login error:", e);

    return res.status(500).json({
      error: "Could not login right now.",
    });
  }
});

/* =========================
   LOGOUT
========================= */

app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({
    ok: true,
  });
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/me", auth, async (req, res) => {
  try {
    const user = await getUserById(req.user.id);

    if (!user) {
      return res.status(401).json({
        error: "Account not found",
      });
    }

    return res.json({
      id: user.id,
      email: user.email,
      plan: user.plan,
      subscription_id: user.subscription_id,
      subscription_status: user.subscription_status,
      created_at: user.created_at,
    });
  } catch (e) {
    console.error("Me error:", e);

    return res.status(500).json({
      error: "Could not load account.",
    });
  }
});

/* =========================
   CREATE RAZORPAY SUBSCRIPTION
========================= */

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

  try {
    const user = await getUserById(req.user.id);

    if (!user) {
      return res.status(401).json({
        error: "Account not found",
      });
    }

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
      total_count: 12,
      quantity: 1,
      customer_notify: 1,
      notes: {
        creatorai_user_id: String(user.id),
        email: user.email,
      },
    });

    const { error } = await supabase
      .from("users")
      .update({
        subscription_id: sub.id,
        subscription_status: sub.status,
      })
      .eq("id", user.id);

    if (error) {
      console.error("Subscription DB update error:", error);

      return res.status(500).json({
        error: "Subscription created but account could not be updated.",
      });
    }

    return res.json({
      subscriptionId: sub.id,
      keyId: process.env.RAZORPAY_KEY_ID,
    });
  } catch (e) {
    console.error("Create subscription error:", e);

    return res.status(500).json({
      error:
        e.error?.description ||
        e.message ||
        "Could not create subscription.",
    });
  }
});

/* =========================
   VERIFY RAZORPAY SUBSCRIPTION
========================= */

app.post("/api/verify-subscription", auth, async (req, res) => {
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

  try {
    const user = await getUserById(req.user.id);

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
      razorpay_signature.length !== expected.length ||
      !crypto.timingSafeEqual(
        Buffer.from(expected),
        Buffer.from(razorpay_signature)
      )
    ) {
      return res.status(400).json({
        error: "Payment verification failed.",
      });
    }

    const { error } = await supabase
      .from("users")
      .update({
        plan: "pro",
        subscription_status: "authenticated",
      })
      .eq("id", user.id);

    if (error) {
      console.error("Payment DB update error:", error);

      return res.status(500).json({
        error: "Payment verified but account could not be updated.",
      });
    }

    return res.json({
      ok: true,
      plan: "pro",
      subscription_status: "authenticated",
    });
  } catch (e) {
    console.error("Verify subscription error:", e);

    return res.status(500).json({
      error: "Could not verify payment.",
    });
  }
});

/* =========================
   AI IMAGE GENERATION
========================= */

/* =========================
   CREATORAI BRAIN — GEMINI
========================= */


// =========================
// OPTIONAL CLAUDE PROVIDER
// =========================

async function callClaude(systemPrompt, userPrompt) {
  const response = await fetch(
    "https://api.anthropic.com/v1/messages",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": process.env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-6",
        max_tokens: 3000,
        system: systemPrompt,
        messages: [
          {
            role: "user",
            content: userPrompt,
          },
        ],
      }),
    }
  );

  const data = await response.json();

  // Normalize Claude's response so the existing
  // CreatorAI Brain response handling can use it.
  if (response.ok && data?.content?.length) {
    const text = data.content
      .map((part) => part.text || "")
      .join("")
      .trim();

    return {
      response,
      data: {
        candidates: [
          {
            content: {
              parts: [
                {
                  text,
                },
              ],
            },
          },
        ],
      },
    };
  }

  return {
    response,
    data,
  };
}

app.post("/api/brain", auth, async (req, res) => {
  try {
    const user = await getUserById(req.user.id);

    if (!user || user.plan !== "pro") {
      return res.status(403).json({
        error: "Creator Pro is required. Upgrade for ₹199/month.",
      });
    }

    const { idea, type = "video" } = req.body || {};

    if (!idea || idea.trim().length < 5) {
      return res.status(400).json({
        error: "Tell CreatorAI what you want to create.",
      });
    }

    if (!process.env.GEMINI_API_KEY) {
      return res.status(503).json({
        error: "Gemini AI is not configured.",
      });
    }

    const systemPrompt = `
You are CreatorAI Brain — an expert AI creative director.

Your job is NOT simply to rewrite the user's idea.

Understand the user's intent, audience, language, emotion, platform
and desired outcome, then turn the thought into a production-ready
content concept.

For every idea determine:

1. What the user actually wants.
2. Target audience.
3. Language and cultural context.
4. Best content format.
5. Powerful opening hook.
6. Story/concept.
7. Complete short-form script where appropriate.
8. Scene-by-scene visual direction.
9. Dialogue and voice direction.
10. Music/SFX direction.
11. Camera and editing direction.
12. Caption.
13. Title options.
14. Relevant hashtags.
15. Production prompt for future AI video/image/audio models.

For short videos prioritize:
- first 1–2 second hook
- fast pacing
- curiosity
- emotional or comedic payoff
- relatable situations
- strong ending
- vertical/mobile-first storytelling

For Punjabi or Hindi content, use natural conversational language.

For comedy, create an actual joke/story with setup, escalation and payoff.

For emotional content, create emotional progression rather than generic
motivational language.

For educational content, make the explanation simple and engaging.

Never promise that content will go viral. Optimize using proven
short-form storytelling principles.

Do not copy copyrighted characters, scripts, songs or creators.
Create original concepts.

Return a clean, highly useful CreatorAI production plan.
`;

    const userPrompt = `
CONTENT TYPE: ${type}

USER'S ORIGINAL THOUGHT:
${idea}

Create the best possible CreatorAI production plan from this thought.
`;

    async function callGemini(model) {
      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-goog-api-key": process.env.GEMINI_API_KEY,
          },
          body: JSON.stringify({
            systemInstruction: {
              parts: [
                {
                  text: systemPrompt,
                },
              ],
            },
            contents: [
              {
                role: "user",
                parts: [
                  {
                    text: userPrompt,
                  },
                ],
              },
            ],
            generationConfig: {
              maxOutputTokens: 3000,
            },
          }),
        }
      );

      const data = await response.json();

      return {
        response,
        data,
      };
    }

    // =========================
// CREATORAI MODEL ROUTER
// =========================

// =========================
// CREATORAI MULTI-MODEL ROUTER
// =========================

const contentText = `${idea} ${type}`.toLowerCase();

let selectedProvider = "gemini";

// Claude is optional.
// Gemini remains the default provider.
// Claude activates only when BOTH:
// 1. CREATORAI_BRAIN_PROVIDER = "claude"
// 2. ANTHROPIC_API_KEY exists

if (
  process.env.CREATORAI_BRAIN_PROVIDER === "claude" &&
  process.env.ANTHROPIC_API_KEY
) {
  selectedProvider = "claude";
}

console.log(
  "CreatorAI selected provider:",
  selectedProvider
);

let result;

// =========================
// CLAUDE
// =========================

if (selectedProvider === "claude") {
  result = await callClaude(
    systemPrompt,
    userPrompt
  );

  // If Claude fails, automatically fall back to Gemini.
  if (!result.response.ok) {
    console.log(
      `Claude unavailable (${result.response.status}). Falling back to Gemini 3.7 Flash...`
    );

    result = await callGemini("gemini-3.7-flash");
  }
}

// =========================
// GEMINI
// =========================

else {
  result = await callGemini("gemini-3.7-flash");

  // Automatic Gemini fallback
  if (
    !result.response.ok &&
    [429, 500, 502, 503, 504].includes(
      result.response.status
    )
  ) {
    console.log(
      `Gemini 3.7 Flash unavailable (${result.response.status}). Trying Gemini 3.6 Flash...`
    );

    result = await callGemini("gemini-3.6-flash");
  }
}
  
    if (!result.response.ok) {
      console.error("Gemini Brain error:", result.data);

      return res.status(502).json({
        error:
          result.data?.error?.message ||
          "CreatorAI Brain is temporarily unavailable. Please try again.",
      });
    }

    const text =
      result.data?.candidates?.[0]?.content?.parts
        ?.map((part) => part.text || "")
        .join("")
        .trim();

    if (!text) {
      return res.status(502).json({
        error: "Gemini returned no creative plan.",
      });
    }

    return res.json({
      ok: true,
      status: "completed",
      type,
      idea,
      result: text,
    });

  } catch (error) {
    console.error("CreatorAI Brain error:", error);

    return res.status(500).json({
      error: "CreatorAI Brain is temporarily unavailable.",
    });
  }
 });

/* =========================
   CREATORAI VOICE — GEMINI TTS
   Automatic multilingual voice
========================= */

app.post("/api/tts", auth, async (req, res) => {
  try {
    const user = await getUserById(req.user.id);

    if (!user || user.plan !== "pro") {
      return res.status(403).json({
        error: "Creator Pro is required. Upgrade for ₹199/month.",
      });
    }

    const { text, voice = "Kore" } = req.body || {};

    if (!text || text.trim().length < 1) {
      return res.status(400).json({
        error: "No voice script was provided.",
      });
    }

    if (!process.env.GEMINI_API_KEY) {
      return res.status(503).json({
        error: "Gemini AI is not configured.",
      });
    }

    const response = await fetch(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-tts-preview:generateContent",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-goog-api-key": process.env.GEMINI_API_KEY,
        },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                {
                  text:
                    "Speak the following text naturally and clearly. " +
                    "Automatically detect the language and speak in the same " +
                    "language. Do not translate. Preserve the original words " +
                    "and meaning.\n\n" +
                    text.trim(),
                },
              ],
            },
          ],
          generationConfig: {
            responseModalities: ["AUDIO"],
            speechConfig: {
              voiceConfig: {
                prebuiltVoiceConfig: {
                  voiceName: voice,
                },
              },
            },
          },
        }),
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error("Gemini TTS error:", data);

      return res.status(502).json({
        error:
          data?.error?.message ||
          "CreatorAI Voice is temporarily unavailable.",
      });
    }

    const audioBase64 =
      data?.candidates?.[0]?.content?.parts?.find(
        (part) => part?.inlineData?.data
      )?.inlineData?.data;

    if (!audioBase64) {
      return res.status(502).json({
        error: "Gemini returned no audio.",
      });
    }

    const pcm = Buffer.from(audioBase64, "base64");

    const sampleRate = 24000;
    const numChannels = 1;
    const bitsPerSample = 16;

    const byteRate =
      sampleRate * numChannels * (bitsPerSample / 8);

    const blockAlign =
      numChannels * (bitsPerSample / 8);

    const wav = Buffer.alloc(44 + pcm.length);

    wav.write("RIFF", 0);
    wav.writeUInt32LE(36 + pcm.length, 4);
    wav.write("WAVE", 8);

    wav.write("fmt ", 12);
    wav.writeUInt32LE(16, 16);
    wav.writeUInt16LE(1, 20);
    wav.writeUInt16LE(numChannels, 22);
    wav.writeUInt32LE(sampleRate, 24);
    wav.writeUInt32LE(byteRate, 28);
    wav.writeUInt16LE(blockAlign, 32);
    wav.writeUInt16LE(bitsPerSample, 34);

    wav.write("data", 36);
    wav.writeUInt32LE(pcm.length, 40);

    pcm.copy(wav, 44);

    return res.json({
      ok: true,
      status: "completed",
      type: "audio",
      mimeType: "audio/wav",
      audioBase64: wav.toString("base64"),
    });

  } catch (error) {
    console.error("CreatorAI TTS error:", error);

    return res.status(500).json({
      error: "Unable to generate voice audio right now.",
    });
  }
});

app.post("/api/generate", auth, async (req, res) => {
  try {
    const user = await getUserById(req.user.id);

    if (!user || user.plan !== "pro") {
      return res.status(403).json({
        error: "Creator Pro is required. Upgrade for ₹199/month.",
      });
    }

    const { prompt, type = "image" } = req.body || {};

    if (!prompt || prompt.length < 5) {
      return res.status(400).json({
        error: "Enter a prompt.",
      });
    }

    if (!process.env.FAL_KEY) {
      return res.status(503).json({
        error: "AI service is not configured.",
      });
    }

    /* =========================
       IMAGE GENERATION
    ========================= */

    if (type === "image") {
      const falResponse = await fetch(
        "https://fal.run/fal-ai/flux/schnell",
        {
          method: "POST",
          headers: {
            Authorization: `Key ${process.env.FAL_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            prompt,
            image_size: "square_hd",
            num_images: 1,
            output_format: "jpeg",
            enable_safety_checker: true,
          }),
        }
      );

      const data = await falResponse.json();

      if (!falResponse.ok) {
        console.error("FAL image error:", data);

        return res.status(502).json({
          error:
            data?.detail ||
            data?.error ||
            data?.message ||
            `FAL image request failed with status ${falResponse.status}`,
        });
      }

      const imageUrl = data?.images?.[0]?.url;

      if (!imageUrl) {
        return res.status(502).json({
          error: "AI returned no image.",
        });
      }

      return res.json({
        ok: true,
        status: "completed",
        type: "image",
        prompt,
        imageUrl,
      });
    }

    /* =========================
       VIDEO GENERATION
    ========================= */

    if (type === "video") {
      const falResponse = await fetch(
        "https://fal.run/fal-ai/veo3.1",
        {
          method: "POST",
          headers: {
            Authorization: `Key ${process.env.FAL_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            prompt,
            aspect_ratio: "9:16",
            duration: "5s",
          }),
        }
      );

      const data = await falResponse.json();

       if (!falResponse.ok) {
  console.error("FAL video error:", data);

  const falError =
    data?.detail ||
    data?.error ||
    data?.message ||
    "";

  if (
    String(falError).toLowerCase().includes("top_up") ||
    String(falError).toLowerCase().includes("user is locked")
  ) {
    return res.status(503).json({
      error:
        "🎬 CreatorAI Video is temporarily unavailable. Our AI video provider is currently being activated. Please try again later.",
    });
  }

  return res.status(502).json({
    error:
      falError ||
      `Video generation failed with status ${falResponse.status}.`,
  });
}

      const videoUrl =
        data?.video?.url ||
        data?.videos?.[0]?.url ||
        data?.output?.video?.url;

      if (!videoUrl) {
        console.error("FAL video returned no URL:", data);

        return res.status(502).json({
          error: "AI returned no video.",
        });
      }

      return res.json({
        ok: true,
        status: "completed",
        type: "video",
        prompt,
        videoUrl,
      });
    }

    return res.status(400).json({
      error: "Unsupported generation type.",
    });

  } catch (error) {
    console.error("FAL generation error:", error);

    return res.status(500).json({
      error: "Unable to generate content right now.",
    });
  }
});
   
/* =========================
   TRADER PRO — CHART ANALYZER
========================= */

app.post("/api/trader-chart", auth, async (req, res) => {
  try {
    const user = await getUserById(req.user.id);

    if (!user || user.plan !== "pro") {
      return res.status(403).json({
        error: "Trader Pro is required. Upgrade to Trader Pro to analyze charts.",
      });
    }

    const {
      imageBase64,
      mimeType = "image/jpeg",
      symbol = "",
      timeframe = "15 minute",
      question = "",
    } = req.body || {};

    if (!imageBase64) {
      return res.status(400).json({
        error: "Please upload a chart screenshot.",
      });
    }

    if (!process.env.GEMINI_API_KEY) {
      return res.status(503).json({
        error: "Gemini AI is not configured.",
      });
    }

    const allowedTypes = ["image/jpeg", "image/png", "image/webp"];
    if (!allowedTypes.includes(mimeType)) {
      return res.status(400).json({
        error: "Please upload a JPG, PNG or WEBP chart image.",
      });
    }

    const chartPrompt = `
You are CreatorAI Trader Pro, an educational intraday trading copilot for Indian students and beginner traders.

Analyze the uploaded chart image carefully. The chart may be from TradingView, NSE, BSE or another charting platform.

User context:
Symbol: ${symbol || "not supplied"}
Timeframe: ${timeframe}
User question: ${question || "not supplied"}

IMPORTANT RULES:
- Analyze only what is actually visible in the chart and the user context.
- Do not invent current market price, news, volume, indicators, support/resistance, candle patterns or levels that are not visible.
- If a level or indicator cannot be read confidently, say "not clearly visible".
- Do not guarantee profit, predict certainty, or call any setup a sure-shot trade.
- Focus on intraday trading education and risk awareness.
- Keep the language simple enough for a beginner in India.
- If the image is not a trading chart, clearly say so.

Return exactly these sections:

1. CHART SNAPSHOT
Briefly describe the visible timeframe, trend/structure and instrument if identifiable.

2. WHAT I CAN SEE
3 to 6 short bullets covering only visible features.

3. POSSIBLE INTRADAY SCENARIOS
Give a bullish scenario and a bearish scenario only when the chart supports them.
For each, state what confirmation would strengthen it.
Do not invent price levels.

4. KEY LEVELS
List visible support, resistance, high/low or marked levels.
If levels are unreadable, say so.

5. WHAT COULD GO WRONG
3 short beginner-friendly warnings.

6. BEGINNER CHECKLIST
4 practical checks before entering an intraday trade.

7. VERDICT
Choose one:
- SETUP LOOKS INTERESTING — WAIT FOR CONFIRMATION
- NOT ENOUGH CONFIRMATION
- AVOID / REWORK
Explain why in 1-2 sentences.

8. EDUCATIONAL NOTE
One sentence: this is chart analysis, not a guaranteed signal or personalized investment advice.
`;

    const requestBody = {
      systemInstruction: {
        parts: [{
          text: "You are a careful visual chart analyst. Never invent information that is not visible.",
        }],
      },
      contents: [{
        role: "user",
        parts: [
          { text: chartPrompt },
          {
            inlineData: {
              mimeType,
              data: imageBase64,
            },
          },
        ],
      }],
      generationConfig: {
        maxOutputTokens: 2500,
      },
    };

    const chartModels = ["gemini-3.7-flash", "gemini-3.6-flash"];
    let lastError = null;

    for (const model of chartModels) {
      try {
        const response = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "x-goog-api-key": process.env.GEMINI_API_KEY,
            },
            body: JSON.stringify(requestBody),
          }
        );

        const data = await response.json();

        if (response.ok) {
          const text = data?.candidates?.[0]?.content?.parts
            ?.map((part) => part.text || "")
            .join("")
            .trim();

          if (text) {
            return res.json({
              ok: true,
              status: "completed",
              type: "trader-chart",
              result: text,
            });
          }

          lastError = "The AI returned no chart analysis.";
        } else {
          lastError = data?.error?.message || `Model ${model} was unavailable.`;
          console.error(`Trader chart ${model} error:`, data);
        }
      } catch (modelError) {
        lastError = modelError?.message || `Model ${model} failed.`;
        console.error(`Trader chart ${model} request error:`, modelError);
      }
    }

    return res.status(502).json({
      error: "CreatorAI's chart AI is temporarily busy. Please try again in a moment.",
      detail: lastError || undefined,
    });
  } catch (error) {
    console.error("Trader chart error:", error);
    return res.status(500).json({
      error: "Unable to analyze the chart right now.",
    });
  }
});

/* =========================
   TRADER PRO — ONE-CLICK ENGINE
   Practice / paper mode only
========================= */

const TRADER_SYMBOLS = [
  "RELIANCE","TCS","HDFCBANK","ICICIBANK","INFY","SBIN",
  "BHARTIARTL","ITC","LT","AXISBANK","KOTAKBANK","MARUTI",
  "SUNPHARMA","TATAMOTORS","TATASTEEL","ADANIENT","M&M",
  "BAJFINANCE","HINDUNILVR"
];

function normalizeTraderSymbol(symbol) {
  const raw = String(symbol || "").trim().toUpperCase().replace(/[^A-Z0-9&-]/g, "");
  if (raw === "NIFTY50" || raw === "NIFTY") return "^NSEI";
  return raw;
}

async function fetchYahooIntraday(symbol) {
const normalizedSymbol = normalizeTraderSymbol(symbol);
const yahooSymbol = normalizedSymbol.startsWith("^")
  ? normalizedSymbol
  : `${normalizedSymbol}.NS`;
const encoded = encodeURIComponent(yahooSymbol);
  const url = `https://query1.finance.yahoo.com/v8/finance/chart/${encoded}?range=1d&interval=5m&includePrePost=false`;
  const r = await fetch(url, {
    headers: { "User-Agent": "CreatorAI-Trader/1.0" }
  });

  const data = await r.json();

  if (!r.ok) {
    throw new Error(
      data?.chart?.error?.description ||
      `Market data unavailable (${r.status})`
    );
  }

  const result = data?.chart?.result?.[0];
  const q = result?.indicators?.quote?.[0];

  const closes = (q?.close || [])
    .map(Number)
    .filter(Number.isFinite);

  const volumes = (q?.volume || []).map(Number);

  if (closes.length < 12) {
    throw new Error("Not enough recent market data.");
  }

  const price = closes[closes.length - 1];
  const prev = closes[closes.length - 7];

  const momentum = ((price - prev) / prev) * 100;

  const recent = closes.slice(-12);
  const high = Math.max(...recent);
  const low = Math.min(...recent);

  const validVolumes = volumes
    .slice(-12)
    .filter(Number.isFinite);

  const avgVolume =
    validVolumes.reduce((a,b) => a+b,0) /
    Math.max(1, validVolumes.length);

  const lastVolume =
    Number(volumes[volumes.length - 1]) || 0;

  return {
    symbol: String(symbol || "").toUpperCase(),
    price: Number(price.toFixed(2)),
    momentum: Number(momentum.toFixed(2)),
    high: Number(high.toFixed(2)),
    low: Number(low.toFixed(2)),
    volumeRatio:
      avgVolume > 0
        ? Number((lastVolume / avgVolume).toFixed(2))
        : null,
    closes: closes
      .slice(-24)
      .map(v => Number(v.toFixed(2)))
  };
}

function deterministicTraderPlan(
  market,
  capital,
  maxLoss,
  profitGoal,
  style
) {
  const price = market.price;

  const bullish = market.momentum > 0.12;
  const bearish = market.momentum < -0.12;

  if (!bullish && !bearish) {
    return {
      verdict: "WAIT",
      symbol: market.symbol,
      direction: "WAIT",
      entry: null,
      stopLoss: null,
      target: null,
      quantity: 0,
      maxLoss: 0,
      potentialProfit: 0,
      simple_reason:
        "Recent price movement is too mixed for the practice engine to create a clean directional setup.",
      explanation:
        "CreatorAI did not find enough directional momentum in the available recent candles. Waiting is allowed and often safer than forcing a trade.",
      warning:
        "No simulated order was created because the setup did not pass the basic direction filter."
    };
  }

  const direction = bullish ? "BUY" : "SELL";

  const riskPerShare = Math.max(
    price *
      (
        style === "conservative"
          ? 0.004
          : style === "balanced"
          ? 0.006
          : 0.008
      ),
    0.05
  );

  const targetDistance = Math.max(
    riskPerShare * 2,
    profitGoal > 0
      ? profitGoal /
        Math.max(
          1,
          Math.floor(maxLoss / riskPerShare)
        )
      : riskPerShare * 2
  );

  const quantity = Math.max(
    0,
    Math.floor(
      Math.min(
        capital / price,
        maxLoss / riskPerShare
      )
    )
  );

  if (quantity < 1) {
    return {
      verdict: "NO TRADE",
      symbol: market.symbol,
      direction,
      entry: price,
      stopLoss: null,
      target: null,
      quantity: 0,
      maxLoss: 0,
      potentialProfit: 0,
      simple_reason:
        "Your maximum acceptable loss is too small for even one share at this setup's calculated risk distance.",
      explanation:
        "CreatorAI protects the loss limit rather than increasing the quantity or risk to force a trade.",
      warning:
        "Increase available capital or use a larger acceptable loss only if that still fits your own risk plan."
    };
  }

  const entry = price;

  const stopLoss =
    bullish
      ? entry - riskPerShare
      : entry + riskPerShare;

  const target =
    bullish
      ? entry + targetDistance
      : entry - targetDistance;

  const actualMaxLoss =
    Number((riskPerShare * quantity).toFixed(2));

  const potentialProfit =
    Number((targetDistance * quantity).toFixed(2));

  return {
    verdict: "TRADE",
    symbol: market.symbol,
    direction,
    entry: Number(entry.toFixed(2)),
    stopLoss: Number(stopLoss.toFixed(2)),
    target: Number(target.toFixed(2)),
    quantity,
    maxLoss: actualMaxLoss,
    potentialProfit,
    simple_reason:
      `A ${direction === "BUY" ? "positive" : "negative"} recent momentum reading was detected. CreatorAI built a practice setup while keeping the planned loss below your limit.`,
    explanation:
      `Recent 5-minute movement is ${market.momentum}%. Recent range: ${market.low} to ${market.high}. The engine uses a conservative volatility-based stop and a minimum 1:2 reward-to-risk target.`,
    warning:
      "This is a simulated plan based on available market data. It is not a guaranteed signal, and live prices can change before an order could be filled."
  };
}

async function aiRefineTraderPlan(
  market,
  basePlan,
  capital,
  maxLoss,
  profitGoal,
  style
) {
  if (!process.env.GEMINI_API_KEY) {
    return basePlan;
  }

  const prompt = `You are CreatorAI Trader Pro, a cautious trading decision-support assistant for beginners in India.

Use ONLY the supplied market snapshot and the already-calculated risk limits.

Never invent news, prices or indicators.

Do not guarantee profit.

Do not increase the user's maximum loss.

Market snapshot:
${JSON.stringify(market)}

Calculated base plan:
${JSON.stringify(basePlan)}

User capital: ${capital}

Maximum loss: ${maxLoss}

Profit goal (not guaranteed): ${profitGoal || 0}

Style: ${style}

Return ONLY valid JSON with keys:
verdict, direction, entry, stopLoss, target, quantity, maxLoss, potentialProfit, simple_reason, explanation, warning.

verdict must be TRADE, WAIT, or NO TRADE.

If the base plan is unsafe or unclear, choose WAIT or NO TRADE.

Keep maxLoss <= ${maxLoss}.`;

  const models = [
    "gemini-3.7-flash",
    "gemini-3.6-flash"
  ];

  for (const model of models) {
    try {
      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-goog-api-key":
              process.env.GEMINI_API_KEY
          },
          body: JSON.stringify({
            contents: [
              {
                parts: [
                  { text: prompt }
                ]
              }
            ],
            generationConfig: {
              temperature: 0.1,
              maxOutputTokens: 1200,
              responseMimeType: "application/json"
            }
          })
        }
      );

      const data = await response.json();

      if (!response.ok) continue;

      const text =
        data?.candidates?.[0]?.content?.parts
          ?.map(p => p.text || "")
          .join("")
          .trim();

      if (!text) continue;

      const cleaned = text
        .replace(/^```json\s*/i, "")
        .replace(/```$/i, "")
        .trim();

      const parsed = JSON.parse(cleaned);

      if (
        !parsed ||
        !["TRADE","WAIT","NO TRADE"]
          .includes(parsed.verdict)
      ) {
        continue;
      }

      if (Number(parsed.maxLoss) > maxLoss + 0.01) {
        return basePlan;
      }

      return {
        ...basePlan,
        ...parsed,
        symbol: market.symbol
      };

    } catch (e) {
      console.error(
        `Trader AI ${model} error:`,
        e
      );
    }
  }

  return basePlan;
}

app.post(
  "/api/trader-opportunities",
  auth,
  async (req, res) => {
    try {
      const user =
        await getUserById(req.user.id);

      if (!user || user.plan !== "pro") {
        return res.status(403).json({
          error: "Trader Pro is required."
        });
      }

      const {
        capital = 0,
        maxLoss = 0,
        style = "conservative"
      } = req.body || {};

      if (
        !capital ||
        !maxLoss ||
        maxLoss >= capital
      ) {
        return res.status(400).json({
          error:
            "Enter a valid amount and a smaller maximum loss."
        });
      }

      const results = [];

      for (
        const symbol of TRADER_SYMBOLS.slice(0, 12)
      ) {
        try {
          const m =
            await fetchYahooIntraday(symbol);

          if (
            Math.abs(m.momentum) >=
            (
              style === "conservative"
                ? 0.25
                : 0.15
            )
          ) {
            results.push({
              ...m,
              direction:
                m.momentum > 0
                  ? "BUY"
                  : "SELL",
              reason:
                m.momentum > 0
                  ? "Positive recent momentum"
                  : "Negative recent momentum"
            });
          }

        } catch (e) {
          console.error(
            "Opportunity scan",
            symbol,
            e.message
          );
        }
      }

      results.sort(
        (a,b) =>
          Math.abs(b.momentum) -
          Math.abs(a.momentum)
      );

      return res.json({
        ok: true,
        opportunities:
          results.slice(0, 5),
        dataNote:
          "Market data is retrieved from a public market-data endpoint and may be delayed or unavailable."
      });

    } catch (e) {
      console.error(
        "Opportunity scanner error:",
        e
      );

      return res.status(500).json({
        error:
          "CreatorAI could not scan the market right now."
      });
    }
  }
);

app.post(
  "/api/trader-plan",
  auth,
  async (req, res) => {
    try {
      const user =
        await getUserById(req.user.id);

      if (!user || user.plan !== "pro") {
        return res.status(403).json({
          error: "Trader Pro is required."
        });
      }

      const {
        symbol = "",
        capital = 0,
        maxLoss = 0,
        profitGoal = 0,
        style = "conservative",
        action = "paper"
      } = req.body || {};

      if (
        !capital ||
        capital < 1000 ||
        !maxLoss ||
        maxLoss <= 0 ||
        maxLoss >= capital
      ) {
        return res.status(400).json({
          error:
            "Enter a valid amount and maximum acceptable loss."
        });
      }

      if (!symbol) {
        return res.status(400).json({
          error:
            "Choose a stock or use 'Find for me'."
        });
      }

      let market;

      try {
        market =
          await fetchYahooIntraday(symbol);
      } catch (e) {
        return res.status(503).json({
          error:
            "Current market data is unavailable for this symbol. Try another liquid NSE stock or try again later."
        });
      }

      let plan =
        deterministicTraderPlan(
          market,
          Number(capital),
          Number(maxLoss),
          Number(profitGoal),
          style
        );

      plan =
        await aiRefineTraderPlan(
          market,
          plan,
          Number(capital),
          Number(maxLoss),
          Number(profitGoal),
          style
        );

      if (
        plan.quantity &&
        plan.entry &&
        plan.stopLoss
      ) {
        const riskPerUnit =
          Math.abs(
            Number(plan.entry) -
            Number(plan.stopLoss)
          );

        const safeQty =
          Math.floor(
            Math.min(
              Number(capital) /
                Number(plan.entry),
              Number(maxLoss) /
                Math.max(
                  riskPerUnit,
                  0.0001
                )
            )
          );

        plan.quantity =
          Math.max(
            0,
            Math.min(
              Number(plan.quantity) || 0,
              safeQty
            )
          );

        plan.maxLoss =
          Number(
            (
              riskPerUnit *
              plan.quantity
            ).toFixed(2)
          );

        if (plan.target) {
          plan.potentialProfit =
            Number(
              (
                Math.abs(
                  Number(plan.target) -
                  Number(plan.entry)
                ) *
                plan.quantity
              ).toFixed(2)
            );
        }

        if (
          plan.maxLoss >
          Number(maxLoss) + 0.01
        ) {
          return res.status(200).json({
            ok: true,
            plan: {
              ...plan,
              verdict: "NO TRADE",
              quantity: 0,
              maxLoss: 0,
              potentialProfit: 0,
              warning:
                "Risk validation rejected this plan."
            }
          });
        }
      }

      let paperTrade = null;

      if (
        action === "paper" &&
        plan.verdict === "TRADE" &&
        plan.quantity > 0
      ) {
        paperTrade = {
          status: "OPEN (SIMULATED)",
          symbol: plan.symbol,
          direction: plan.direction,
          entry: plan.entry,
          quantity: plan.quantity,
          message:
            "🧪 Practice trade created. This is simulated only; no broker order was sent."
        };
      }

      return res.json({
        ok: true,
        plan,
        paperTrade,
        market: {
          price: market.price,
          momentum: market.momentum,
          volumeRatio: market.volumeRatio
        },
        dataNote:
          "Market data may be delayed or unavailable. Practice mode does not place real orders."
      });

    } catch (e) {
      console.error(
        "Trader plan error:",
        e
      );

      return res.status(500).json({
        error:
          "CreatorAI could not build the trade plan right now."
      });
    }
  }
);

/* =========================
   FRONTEND FALLBACK
========================= */

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
