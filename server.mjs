import http from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";

const PORT = Number(process.env.PORT || 8080);
const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "Content-Type, Stripe-Signature, stripe-signature",
};

function json(res, body, status = 200) {
  res.writeHead(status, { "content-type": "application/json", ...CORS });
  res.end(JSON.stringify(body));
}

function stripeMode(key) {
  if (!key) return "off";
  return key.startsWith("sk_live_") ? "live" : "test";
}

async function stripeGet(key, path) {
  const res = await fetch(`https://api.stripe.com/v1/${path}`, {
    headers: { authorization: `Bearer ${key}` },
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || `Stripe ${res.status}`);
  return data;
}

function methodFrom(pm) {
  if (!pm || typeof pm === "string") {
    return { paymentKind: "card", cardBrand: "Card", cardLast4: null, applePay: false };
  }
  const apple = pm.card?.wallet?.type === "apple_pay";
  return {
    paymentKind: apple ? "apple_pay" : "card",
    cardBrand: apple ? "Apple Pay" : pm.card?.brand || pm.type || "Card",
    cardLast4: pm.card?.last4 ?? null,
    applePay: apple,
  };
}

function packageFrom(session, sub) {
  return (
    session.metadata?.packageId ||
    sub?.metadata?.packageId ||
    session.subscription_details?.metadata?.packageId ||
    "signal"
  );
}

function paidPayload(session, userId) {
  const sub = typeof session.subscription === "object" ? session.subscription : null;
  let pm = sub?.default_payment_method;
  if (!pm || typeof pm === "string") {
    const setup = typeof session.setup_intent === "object" ? session.setup_intent : null;
    pm = setup?.payment_method ?? pm;
  }
  const method = methodFrom(typeof pm === "object" ? pm : null);
  return {
    ok: true,
    userId,
    packageId: packageFrom(session, sub),
    ...method,
    customerId: typeof session.customer === "string" ? session.customer : session.customer?.id ?? null,
    subscriptionId: typeof session.subscription === "string" ? session.subscription : sub?.id ?? null,
    sessionId: session.id,
  };
}

function ownsSession(session, userId) {
  if (!userId) return false;
  if (session.metadata?.userId && session.metadata.userId !== userId) return false;
  if (session.client_reference_id && session.client_reference_id !== userId) return false;
  return session.metadata?.userId === userId || session.client_reference_id === userId;
}

function isPaid(session) {
  if (session.status && session.status !== "complete") return false;
  if (session.payment_status === "unpaid") return false;
  return true;
}

async function lookupSession(key, sessionId, userId) {
  const expand =
    "expand[]=subscription.default_payment_method&expand[]=setup_intent.payment_method";
  const session = await stripeGet(key, `checkout/sessions/${sessionId}?${expand}`);
  if (!isPaid(session)) return { status: 402, body: { ok: false, error: "not_paid" } };
  if (userId && !ownsSession(session, userId)) {
    return { status: 403, body: { ok: false, error: "wrong_account" } };
  }
  const uid = userId || session.metadata?.userId || session.client_reference_id;
  if (!uid) return { status: 422, body: { ok: false, error: "no_user" } };
  return { status: 200, body: paidPayload(session, uid) };
}

async function lookupByUser(key, userId) {
  const list = await stripeGet(
    key,
    `checkout/sessions?client_reference_id=${encodeURIComponent(userId)}&limit=10`,
  );
  const session = (list.data || []).find(isPaid);
  if (!session) return { status: 404, body: { ok: false, error: "not_found" } };
  return lookupSession(key, session.id, userId);
}

function verifyWebhook(raw, header, secret) {
  const parts = Object.fromEntries(
    header.split(",").map((p) => {
      const i = p.indexOf("=");
      return [p.slice(0, i).trim(), p.slice(i + 1).trim()];
    }),
  );
  if (!parts.t || !parts.v1) throw new Error("bad_header");
  const digest = createHmac("sha256", secret).update(`${parts.t}.${raw}`).digest("hex");
  const a = Buffer.from(digest);
  const b = Buffer.from(parts.v1);
  if (a.length !== b.length || !timingSafeEqual(a, b)) throw new Error("bad_signature");
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
  if (req.method === "OPTIONS") {
    res.writeHead(204, CORS);
    res.end();
    return;
  }

  const key = (process.env.STRIPE_SECRET_KEY || "").trim();
  const whsec = (process.env.STRIPE_WEBHOOK_SECRET || "").trim();
  const path = url.pathname;

  try {
    if (req.method === "GET" && (path === "/" || path === "/api/stripe")) {
      const sessionId = url.searchParams.get("session_id") || "";
      const userId = url.searchParams.get("user_id") || "";
      if (!key) {
        json(res, {
          configured: false,
          webhook: Boolean(whsec),
          mode: "off",
          endpoint: `${url.origin}/api/stripe`,
        });
        return;
      }
      if (sessionId.startsWith("cs_")) {
        const out = await lookupSession(key, sessionId, userId);
        json(res, out.body, out.status);
        return;
      }
      if (userId) {
        const out = await lookupByUser(key, userId);
        json(res, out.body, out.status);
        return;
      }
      json(res, {
        configured: true,
        webhook: Boolean(whsec),
        mode: stripeMode(key),
        endpoint: `${url.origin}/api/stripe`,
      });
      return;
    }

    if (req.method === "POST" && (path === "/" || path === "/api/stripe")) {
      if (!key) return json(res, { error: "Stripe is not connected" }, 503);
      if (!whsec) return json(res, { error: "Stripe webhook secret is not set" }, 503);
      const signature = req.headers["stripe-signature"] || "";
      if (!signature) return json(res, { error: "Missing Stripe-Signature" }, 401);
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const raw = Buffer.concat(chunks).toString("utf8");
      try {
        verifyWebhook(raw, String(signature), whsec);
      } catch {
        json(res, { error: "bad_signature" }, 401);
        return;
      }
      const event = JSON.parse(raw);
      json(res, { received: true, type: event.type });
      return;
    }

    json(res, { error: "Not found" }, 404);
  } catch (err) {
    json(res, { error: err instanceof Error ? err.message : "bridge_error" }, 500);
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`ando-stripe bridge on :${PORT}`);
});
