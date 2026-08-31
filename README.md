# ANDÖ Stripe bridge

Grok cannot store Stripe keys. This host can. Payment Links stay on josearmando.studio; this process verifies Checkout and the webhook.

## Cloudflare (fastest)

1. [dash.cloudflare.com](https://dash.cloudflare.com) → Workers & Pages → Create → Worker.
2. Name it `ando-stripe`. Paste `worker.js`. Deploy.
3. Settings → Variables: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` (test first).
4. Copy the `*.workers.dev` URL.
5. Stripe → Developers → Webhooks → Add endpoint  
   `https://YOUR-WORKER/api/stripe`  
   events: `checkout.session.completed`, `checkout.session.async_payment_succeeded`, `customer.subscription.deleted`.
6. Paste the new signing secret as `STRIPE_WEBHOOK_SECRET`.
7. Send the workers.dev URL in the ANDÖ Grok chat so the site points at it.

## Railway / Fly

Same `server.mjs`. Env: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `PORT`. Webhook URL: `https://YOUR-HOST/api/stripe`.
