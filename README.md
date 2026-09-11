# CreatorAI — ₹199/month starter

CreatorAI is a starter SaaS app for AI video/image/voice/content creation with login, a creator dashboard and Razorpay recurring subscriptions.

## Razorpay test plan already configured

The project is prefilled with the Test Mode Plan ID:

`plan_TAbSHSSbe9Lbnc`

The app creates a Razorpay Subscription server-side and opens Razorpay Standard Checkout using the returned `subscription_id`. After checkout, the server verifies the subscription signature before activating Creator Pro. Razorpay recommends server-side signature verification and webhooks for subscription integrations.

## 1. Configure environment variables

Copy `.env.example` to `.env` and fill in:

- `RAZORPAY_KEY_ID` — your Test Mode Key ID
- `RAZORPAY_KEY_SECRET` — your Test Mode Key Secret (never put this in frontend code)
- `RAZORPAY_PLAN_ID` — already set to `plan_TAbSHSSbe9Lbnc`
- `RAZORPAY_WEBHOOK_SECRET` — the secret you choose when configuring the webhook
- `JWT_SECRET` — a long random value

## 2. Run locally

```bash
npm install
npm start
```

Open `http://localhost:3000`.

## 3. Test the subscription

1. Create a CreatorAI account.
2. Click **Upgrade to Pro — ₹199/month**.
3. Razorpay Checkout opens.
4. Use Razorpay's current Test Mode subscription/card test details from its documentation.
5. On successful authorisation, Creator Pro is activated only after server-side signature verification.

## 4. Configure Razorpay webhook

In Razorpay Test Mode, create a webhook for:

`https://YOUR-DOMAIN.com/api/razorpay-webhook`

Use a webhook secret and add the same value to `RAZORPAY_WEBHOOK_SECRET`.

For subscriptions, useful events include subscription authenticated/activated, charged, paused, resumed, halted and cancelled events as appropriate for your product. The server verifies the webhook signature using the raw request body.

## 5. Production note

The included SQLite database is suitable for local testing, but a Vercel production deployment should use a hosted database such as Postgres/Supabase rather than a local SQLite file. The next production step is migrating the users/subscriptions table to hosted Postgres.

## 6. AI generation

The dashboard currently has a secure `/api/generate` hook, but no paid AI provider is embedded. Connect your chosen video/image/voice APIs on the server before advertising generation as live. Never expose provider API keys in browser JavaScript.
