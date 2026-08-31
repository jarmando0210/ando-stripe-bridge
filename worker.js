const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "Content-Type, Stripe-Signature, stripe-signature",
};
function json(body, status = 200) {
  return Response.json(body, { status, headers: CORS });
}
async function stripeGet(key, path) {
  const res = await fetch("https://api.stripe.com/v1/" + path, {
    headers: { authorization: "Bearer " + key },
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || "Stripe " + res.status);
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
function isPaid(session) {
  if (session.status && session.status !== "complete") return false;
  return session.payment_status !== "unpaid";
}
function owns(session, userId) {
  if (!userId) return false;
  if (session.metadata?.userId && session.metadata.userId !== userId) return false;
  if (session.client_reference_id && session.client_reference_id !== userId) return false;
  return session.metadata?.userId === userId || session.client_reference_id === userId;
}
function payload(session, userId) {
  const sub = typeof session.subscription === "object" ? session.subscription : null;
  let pm = sub && sub.default_payment_method;
  if (!pm || typeof pm === "string") {
    const setup = typeof session.setup_intent === "object" ? session.setup_intent : null;
    pm = (setup && setup.payment_method) || pm;
  }
  const m = methodFrom(typeof pm === "object" ? pm : null);
  return {
    ok: true,
    userId,
    packageId: (session.metadata && session.metadata.packageId) || (sub && sub.metadata && sub.metadata.packageId) || "signal",
    ...m,
    customerId: typeof session.customer === "string" ? session.customer : session.customer && session.customer.id || null,
    subscriptionId: typeof session.subscription === "string" ? session.subscription : sub && sub.id || null,
    sessionId: session.id,
  };
}
async function lookupSession(key, sessionId, userId) {
  const session = await stripeGet(
    key,
    "checkout/sessions/" + sessionId + "?expand[]=subscription.default_payment_method&expand[]=setup_intent.payment_method",
  );
  if (!isPaid(session)) return json({ ok: false, error: "not_paid" }, 402);
  if (userId && !owns(session, userId)) return json({ ok: false, error: "wrong_account" }, 403);
  const uid = userId || (session.metadata && session.metadata.userId) || session.client_reference_id;
  if (!uid) return json({ ok: false, error: "no_user" }, 422);
  return json(payload(session, uid));
}
async function verifyWebhook(raw, header, secret) {
  const parts = Object.fromEntries(
    header.split(",").map((p) => {
      const i = p.indexOf("=");
      return [p.slice(0, i).trim(), p.slice(i + 1).trim()];
    }),
  );
  if (!parts.t || !parts.v1) throw new Error("bad_header");
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(parts.t + "." + raw));
  const hex = [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
  if (hex.length !== parts.v1.length) throw new Error("bad_signature");
  let diff = 0;
  for (let i = 0; i < hex.length; i++) diff |= hex.charCodeAt(i) ^ parts.v1.charCodeAt(i);
  if (diff) throw new Error("bad_signature");
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    const key = (env.STRIPE_SECRET_KEY || "").trim();
    const whsec = (env.STRIPE_WEBHOOK_SECRET || "").trim();
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/api/stripe")) {
      const sessionId = url.searchParams.get("session_id") || "";
      const userId = url.searchParams.get("user_id") || "";
      if (!key) {
        return json({ configured: false, webhook: Boolean(whsec), mode: "off", endpoint: url.origin + "/api/stripe" });
      }
      if (sessionId.startsWith("cs_")) return lookupSession(key, sessionId, userId);
      if (userId) {
        const list = await stripeGet(key, "checkout/sessions?client_reference_id=" + encodeURIComponent(userId) + "&limit=10");
        const session = (list.data || []).find(isPaid);
        if (!session) return json({ ok: false, error: "not_found" }, 404);
        return lookupSession(key, session.id, userId);
      }
      return json({
        configured: true,
        webhook: Boolean(whsec),
        mode: key.startsWith("sk_live_") ? "live" : "test",
        endpoint: url.origin + "/api/stripe",
      });
    }
    if (request.method === "POST" && (url.pathname === "/" || url.pathname === "/api/stripe")) {
      if (!key) return json({ error: "Stripe is not connected" }, 503);
      if (!whsec) return json({ error: "Stripe webhook secret is not set" }, 503);
      const signature = request.headers.get("stripe-signature") || "";
      if (!signature) return json({ error: "Missing Stripe-Signature" }, 401);
      const raw = await request.text();
      try {
        await verifyWebhook(raw, signature, whsec);
      } catch {
        return json({ error: "bad_signature" }, 401);
      }
      return json({ received: true, type: JSON.parse(raw).type });
    }
    return json({ error: "Not found" }, 404);
  },
};
