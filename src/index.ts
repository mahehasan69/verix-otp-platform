interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  BOOTSTRAP_SECRET?: string;
  INBOUND_WEBHOOK_SECRET?: string;
  SESSION_TTL_HOURS?: string;
  APP_NAME?: string;
}

type User = { id: string; email: string; display_name: string; role: "admin" | "customer"; status: "active" | "suspended" };
const json = (data: unknown, status = 200, headers: HeadersInit = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
const uid = () => crypto.randomUUID();
const encoder = new TextEncoder();
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const fromB64 = (value: string) => Uint8Array.from(atob(value), c => c.charCodeAt(0));
const hex = (bytes: Uint8Array) => [...bytes].map(x => x.toString(16).padStart(2, "0")).join("");

async function digest(value: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))));
}

// Cloudflare Workers Web Crypto currently rejects PBKDF2 iteration counts above 100,000.
// Keep registration and login on the same supported work factor.
const PBKDF2_ITERATIONS = 100000;

async function passwordHash(password: string, salt: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: fromB64(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, key, 256);
  return b64(new Uint8Array(bits));
}
async function newPassword(password: string) {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const salt = b64(saltBytes);
  return { salt, hash: await passwordHash(password, salt) };
}
function validEmail(email: unknown): email is string {
  return typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function validPassword(password: unknown): password is string {
  return typeof password === "string" && password.length >= 12 && password.length <= 128;
}
function cookieToken(request: Request): string | null {
  const raw = request.headers.get("cookie") || "";
  const match = raw.match(/(?:^|;\s*)verix_session=([A-Za-z0-9_-]+)/);
  return match?.[1] || null;
}
function sessionCookie(token: string, maxAge: number) {
  return `verix_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}
async function currentUser(request: Request, env: Env): Promise<User | null> {
  const token = cookieToken(request);
  if (!token) return null;
  const tokenHash = await digest(token);
  const row = await env.DB.prepare(
    "SELECT u.id,u.email,u.display_name,u.role,u.status FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at > datetime('now')"
  ).bind(tokenHash).first<User>();
  return row?.status === "active" ? row : null;
}
async function requireUser(request: Request, env: Env) {
  const user = await currentUser(request, env);
  return user ? { user } : { response: json({ error: "Authentication required" }, 401) };
}
async function requireAdmin(request: Request, env: Env) {
  const auth = await requireUser(request, env);
  if ("response" in auth) return auth;
  if (auth.user.role !== "admin") return { response: json({ error: "Admin access required" }, 403) };
  return auth;
}
async function audit(env: Env, actor: string | null, action: string, target?: string) {
  await env.DB.prepare("INSERT INTO audit_logs(id,actor_user_id,action,target_id) VALUES(?,?,?,?)")
    .bind(uid(), actor, action, target || null).run();
}
function sameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  return !origin || origin === new URL(request.url).origin;
}

async function handleApi(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: { "allow": "GET,POST,OPTIONS" } });
  if (!sameOrigin(request) && path !== "/api/inbound/sms") return json({ error: "Cross-origin request rejected" }, 403);

  if (path === "/api/health" && request.method === "GET") return json({ ok: true, service: "VERIX API" });

  if (path === "/api/admin/bootstrap" && request.method === "POST") {
    if (!env.BOOTSTRAP_SECRET || request.headers.get("x-bootstrap-secret") !== env.BOOTSTRAP_SECRET) return json({ error: "Invalid bootstrap credential" }, 403);
    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM users WHERE role='admin'").first<{count:number}>();
    if ((count?.count || 0) > 0) return json({ error: "Initial admin already exists" }, 409);
    const body = await request.json<{email?:string;displayName?:string;password?:string}>().catch(() => ({}));
    if (!validEmail(body.email) || !validPassword(body.password) || typeof body.displayName !== "string" || body.displayName.trim().length < 2) {
      return json({ error: "Provide a valid email, display name, and password (at least 12 characters)" }, 400);
    }
    const id = uid(); const credentials = await newPassword(body.password);
    await env.DB.prepare("INSERT INTO users(id,email,display_name,password_hash,password_salt,role) VALUES(?,?,?,?,?,'admin')")
      .bind(id, body.email.toLowerCase(), body.displayName.trim(), credentials.hash, credentials.salt).run();
    await audit(env, id, "admin.bootstrap");
    return json({ success: true, message: "First admin created. Remove or rotate BOOTSTRAP_SECRET now." }, 201);
  }

  if (path === "/api/auth/login" && request.method === "POST") {
    const body = await request.json<{email?:string;password?:string}>().catch(() => ({}));
    if (!validEmail(body.email) || typeof body.password !== "string") return json({ error: "Email and password required" }, 400);
    const row = await env.DB.prepare("SELECT id,email,display_name,role,status,password_hash,password_salt FROM users WHERE email=? COLLATE NOCASE")
      .bind(body.email).first<User & {password_hash:string;password_salt:string}>();
    if (!row || row.status !== "active" || await passwordHash(body.password, row.password_salt) !== row.password_hash) {
      return json({ error: "Invalid email or password" }, 401);
    }
    const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
    const token = b64(tokenBytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    const ttl = Math.min(168, Math.max(1, Number(env.SESSION_TTL_HOURS || 24))) * 3600;
    await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,datetime('now',?))")
      .bind(await digest(token), row.id, `+${ttl} seconds`).run();
    await audit(env, row.id, "auth.login");
    return json({ success: true, user: { id: row.id, email: row.email, displayName: row.display_name, role: row.role } }, 200, { "set-cookie": sessionCookie(token, ttl) });
  }

  if (path === "/api/auth/logout" && request.method === "POST") {
    const token = cookieToken(request);
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(token)).run();
    return json({ success: true }, 200, { "set-cookie": sessionCookie("", 0) });
  }

  if (path === "/api/me" && request.method === "GET") {
    const auth = await requireUser(request, env); if ("response" in auth) return auth.response;
    return json({ user: { id: auth.user.id, email: auth.user.email, displayName: auth.user.display_name, role: auth.user.role } });
  }

  if (path === "/api/admin/providers" && request.method === "GET") {
    const auth = await requireAdmin(request, env); if ("response" in auth) return auth.response;
    const rows = await env.DB.prepare("SELECT id,slug,display_name,status,integration_type,created_at FROM provider_accounts ORDER BY created_at DESC").all();
    return json({ providers: rows.results || [] });
  }

  if (path === "/api/admin/providers" && request.method === "POST") {
    const auth = await requireAdmin(request, env); if ("response" in auth) return auth.response;
    const body = await request.json<{slug?:string;displayName?:string;integrationType?:string}>().catch(() => ({}));
    if (typeof body.slug !== "string" || !/^[a-z0-9][a-z0-9-]{1,39}$/.test(body.slug) ||
        typeof body.displayName !== "string" || body.displayName.trim().length < 2 ||
        !["webhook","manual"].includes(body.integrationType || "webhook")) {
      return json({ error: "Provide a provider slug, display name, and integration type (webhook or manual)" }, 400);
    }
    const id = uid();
    try {
      await env.DB.prepare("INSERT INTO provider_accounts(id,slug,display_name,integration_type,status) VALUES(?,?,?,?,'pending')")
        .bind(id, body.slug, body.displayName.trim().slice(0,80), body.integrationType || "webhook").run();
    } catch { return json({ error: "Provider slug already exists or could not be created" }, 409); }
    await audit(env, auth.user.id, "provider.register", id);
    return json({ success: true, providerId: id, status: "pending", message: "Provider registered as pending. No numbers are live until provider access and webhook verification are completed." }, 201);
  }

  if (path === "/api/public/numbers" && request.method === "GET") {
    const rows = await env.DB.prepare("SELECT n.id,n.phone_e164,n.country_code,n.label,m.number_type,m.provider_status FROM phone_numbers n JOIN number_metadata m ON m.number_id=n.id WHERE n.status='active' AND m.number_type='public' AND m.public_access=1 AND m.provider_status='active' AND m.inbound_enabled=1 ORDER BY n.created_at DESC LIMIT 100").all();
    return json({ numbers: rows.results || [] });
  }

  if (path === "/api/admin/users" && request.method === "GET") {
    const auth = await requireAdmin(request, env); if ("response" in auth) return auth.response;
    const rows = await env.DB.prepare("SELECT id,email,display_name,role,status,created_at FROM users ORDER BY created_at DESC LIMIT 200").all();
    return json({ users: rows.results || [] });
  }

  if (path === "/api/admin/numbers" && request.method === "GET") {
    const auth = await requireAdmin(request, env); if ("response" in auth) return auth.response;
    const rows = await env.DB.prepare("SELECT n.id,n.phone_e164,n.country_code,n.label,n.provider,n.status,a.user_id,u.email AS assigned_email FROM phone_numbers n LEFT JOIN number_assignments a ON a.number_id=n.id LEFT JOIN users u ON u.id=a.user_id ORDER BY n.created_at DESC LIMIT 200").all();
    return json({ numbers: rows.results || [] });
  }

  if (path === "/api/admin/users" && request.method === "POST") {
    const auth = await requireAdmin(request, env); if ("response" in auth) return auth.response;
    const body = await request.json<{email?:string;displayName?:string;password?:string}>().catch(() => ({}));
    if (!validEmail(body.email) || !validPassword(body.password) || typeof body.displayName !== "string" || body.displayName.trim().length < 2) {
      return json({ error: "Provide valid email, display name, and a password of at least 12 characters" }, 400);
    }
    const id = uid(); const credentials = await newPassword(body.password);
    try {
      await env.DB.prepare("INSERT INTO users(id,email,display_name,password_hash,password_salt,role) VALUES(?,?,?,?,?,'customer')")
        .bind(id, body.email.toLowerCase(), body.displayName.trim(), credentials.hash, credentials.salt).run();
    } catch { return json({ error: "Could not create user; email may already exist" }, 409); }
    await audit(env, auth.user.id, "customer.create", id);
    return json({ success: true, user: { id, email: body.email.toLowerCase(), displayName: body.displayName.trim(), role: "customer" } }, 201);
  }

  if (path === "/api/admin/numbers" && request.method === "POST") {
    const auth = await requireAdmin(request, env); if ("response" in auth) return auth.response;
    const body = await request.json<{phone?:string;countryCode?:string;label?:string;providerId?:string;providerNumberId?:string;numberType?:string;customerId?:string}>().catch(() => ({}));
    if (typeof body.phone !== "string" || !/^\+[1-9]\d{7,14}$/.test(body.phone) || typeof body.countryCode !== "string" || !/^\+?\d{1,4}$/.test(body.countryCode)) {
      return json({ error: "Use an E.164 phone number and valid country code" }, 400);
    }
    const numberType = body.numberType || "private";
    if (!["public","private"].includes(numberType)) return json({ error: "numberType must be public or private" }, 400);
    if (numberType === "public" && body.customerId) return json({ error: "Public shared numbers cannot be assigned to one customer" }, 400);
    if (numberType === "private" && !body.customerId) return json({ error: "Private numbers must be assigned to one customer" }, 400);
    const customer = body.customerId ? await env.DB.prepare("SELECT id FROM users WHERE id=? AND role='customer' AND status='active'").bind(body.customerId).first() : null;
    if (body.customerId && !customer) return json({ error: "Customer not found" }, 404);
    const provider = body.providerId ? await env.DB.prepare("SELECT id,slug,status FROM provider_accounts WHERE id=?").bind(body.providerId).first<{id:string;slug:string;status:string}>() : null;
    if (!provider || provider.status !== "active") return json({ error: "Select an active, verified provider. Pending/manual numbers cannot receive live SMS." }, 409);
    if (typeof body.providerNumberId !== "string" || !body.providerNumberId.trim()) return json({ error: "Provider number ID is required for provider-backed inventory" }, 400);
    const id = uid();
    try {
      await env.DB.prepare("INSERT INTO phone_numbers(id,phone_e164,country_code,label,provider,status) VALUES(?,?,?,?,?,'active')")
        .bind(id, body.phone, body.countryCode, (body.label || "").slice(0,80), provider.slug).run();
      await env.DB.prepare("INSERT INTO number_metadata(number_id,number_type,provider_id,provider_number_id,provider_status,inbound_enabled,public_access) VALUES(?,?,?,?, 'pending',0,?)")
        .bind(id, numberType, provider.id, body.providerNumberId.trim().slice(0,160), numberType === "public" ? 1 : 0).run();
      if (body.customerId) await env.DB.prepare("INSERT INTO number_assignments(number_id,user_id) VALUES(?,?)").bind(id, body.customerId).run();
    } catch { return json({ error: "Could not add number; it may already exist or assignment failed" }, 409); }
    await audit(env, auth.user.id, "number.inventory.create", id);
    return json({ success: true, numberId: id, numberType, providerStatus: "pending", message: "Inventory saved, but SMS receiving remains disabled until provider verification." }, 201);
  }

  if (path === "/api/inbound/sms" && request.method === "POST") {
    if (!env.INBOUND_WEBHOOK_SECRET || request.headers.get("x-webhook-secret") !== env.INBOUND_WEBHOOK_SECRET) return json({ error: "Unauthorized webhook" }, 401);
    const body = await request.json<{from?:string;to?:string;body?:string;providerMessageId?:string}>().catch(() => ({}));
    if (typeof body.from !== "string" || typeof body.to !== "string" || typeof body.body !== "string" || body.body.length > 5000) {
      return json({ error: "Invalid inbound SMS payload" }, 400);
    }
    const number = await env.DB.prepare("SELECT n.id FROM phone_numbers n JOIN number_metadata m ON m.number_id=n.id JOIN provider_accounts p ON p.id=m.provider_id WHERE n.phone_e164=? AND n.status='active' AND m.provider_status='active' AND m.inbound_enabled=1 AND p.status='active'").bind(body.to).first<{id:string}>();
    if (!number) return json({ error: "Recipient number is not registered with an active, verified inbound provider" }, 404);
    try {
      await env.DB.prepare("INSERT INTO inbound_messages(id,provider_message_id,number_id,sender,body) VALUES(?,?,?,?,?)")
        .bind(uid(), body.providerMessageId || null, number.id, body.from.slice(0,32), body.body).run();
    } catch { return json({ success: true, duplicate: true }); }
    return json({ success: true }, 202);
  }

  if (path === "/api/messages" && request.method === "GET") {
    const auth = await requireUser(request, env); if ("response" in auth) return auth.response;
    const limit = Math.min(100, Math.max(1, Number(url.searchParams.get("limit") || 50)));
    const rows = auth.user.role === "admin"
      ? await env.DB.prepare("SELECT m.id,n.phone_e164,m.sender,m.body,m.received_at,md.number_type FROM inbound_messages m JOIN phone_numbers n ON n.id=m.number_id JOIN number_metadata md ON md.number_id=n.id ORDER BY m.received_at DESC LIMIT ?").bind(limit).all()
      : await env.DB.prepare("SELECT m.id,n.phone_e164,m.sender,m.body,m.received_at,md.number_type FROM inbound_messages m JOIN phone_numbers n ON n.id=m.number_id JOIN number_metadata md ON md.number_id=n.id LEFT JOIN number_assignments a ON a.number_id=n.id WHERE (md.number_type='public' AND md.public_access=1 AND md.provider_status='active') OR (md.number_type='private' AND a.user_id=?) ORDER BY m.received_at DESC LIMIT ?").bind(auth.user.id, limit).all();
    return json({ messages: rows.results || [] });
  }

  if (path.startsWith("/api/")) return json({ error: "Not found" }, 404);
  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try { return await handleApi(request, env); }
    catch (error) {
      console.error("VERIX request failed", error);
      return json({ error: "Internal server error" }, 500);
    }
  }
};