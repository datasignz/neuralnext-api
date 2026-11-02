import {
  createHash,
  randomBytes,
  randomUUID,
  scrypt as scryptCallback,
  timingSafeEqual
} from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);
const portalCookieName = "nn_client_session";
const sessionLifetimeSeconds = 8 * 60 * 60;
const invitationLifetimeHours = 72;
const loginAttempts = new Map();
const allowedRoles = new Set([
  "admin",
  "social_media_manager",
  "content_editor",
  "client",
  "guest"
]);

function hashToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));
  return left.length === right.length && timingSafeEqual(left, right);
}

function getCookie(request, name) {
  const entry = String(request.headers.cookie || "")
    .split(";")
    .map(part => part.trim())
    .find(part => part.startsWith(name + "="));
  if (!entry) return null;
  try { return decodeURIComponent(entry.slice(name.length + 1)); }
  catch { return null; }
}

function setSessionCookie(reply, token) {
  reply.header(
    "Set-Cookie",
    `${portalCookieName}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${sessionLifetimeSeconds}`
  );
}

function clearSessionCookie(reply) {
  reply.header(
    "Set-Cookie",
    `${portalCookieName}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
  );
}

async function makePasswordHash(password) {
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, 64);
  return `scrypt:${salt.toString("hex")}:${Buffer.from(derived).toString("hex")}`;
}

async function verifyPassword(password, stored) {
  const parts = String(stored || "").split(":");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;
  try {
    const expected = Buffer.from(parts[2], "hex");
    const actual = Buffer.from(await scrypt(password, Buffer.from(parts[1], "hex"), expected.length));
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

async function createSession(pool, userId, reply) {
  const rawToken = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + sessionLifetimeSeconds * 1000);
  await pool.query(
    `INSERT INTO user_sessions (id, user_id, token_hash, expires_at)
     VALUES ($1, $2, $3, $4)`,
    [randomUUID(), userId, hashToken(rawToken), expiresAt]
  );
  setSessionCookie(reply, rawToken);
}

async function getPortalUser(pool, request) {
  const token = getCookie(request, portalCookieName);
  if (!token) return null;
  const result = await pool.query(
    `SELECT u.id, u.email, u.full_name, m.organization_id,
            o.name AS organization_name, o.slug AS organization_slug,
            m.role, m.status AS membership_status
     FROM user_sessions s
     JOIN users u ON u.id = s.user_id
     JOIN organization_members m ON m.user_id = u.id AND m.status = 'active'
     JOIN organizations o ON o.id = m.organization_id AND o.status = 'active'
     WHERE s.token_hash = $1
       AND s.revoked_at IS NULL
       AND s.expires_at > NOW()
       AND u.status = 'active'
     ORDER BY o.name`,
    [hashToken(token)]
  );
  if (!result.rowCount) return null;
  await pool.query(
    "UPDATE user_sessions SET last_seen_at=NOW() WHERE token_hash=$1",
    [hashToken(token)]
  );
  return {
    user: {
      id: result.rows[0].id,
      email: result.rows[0].email,
      full_name: result.rows[0].full_name
    },
    memberships: result.rows.map(row => ({
      organization_id: row.organization_id,
      organization_name: row.organization_name,
      organization_slug: row.organization_slug,
      role: row.role
    }))
  };
}

export async function registerClientPortal(app, { pool, isAdminSession }) {
  app.post("/api/portal/admin/invitations", async (request, reply) => {
    if (!isAdminSession(request)) {
      return reply.code(401).send({ success: false, error: "Administrator session required" });
    }
    if (!pool) return reply.code(503).send({ success: false, error: "Database unavailable" });

    const email = String(request.body?.email || "").trim().toLowerCase();
    const slug = String(request.body?.organization_slug || "").trim();
    const role = String(request.body?.role || "client").trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return reply.code(400).send({ success: false, error: "A valid email address is required" });
    }
    if (!allowedRoles.has(role)) {
      return reply.code(400).send({ success: false, error: "Unsupported invitation role" });
    }
    if (!slug) return reply.code(400).send({ success: false, error: "organization_slug is required" });

    try {
      const org = await pool.query(
        "SELECT id, name, slug FROM organizations WHERE slug=$1 AND status='active'",
        [slug]
      );
      if (!org.rowCount) return reply.code(404).send({ success: false, error: "Organisation not found" });

      const rawToken = randomBytes(32).toString("base64url");
      const expiresAt = new Date(Date.now() + invitationLifetimeHours * 60 * 60 * 1000);
      const invitationId = randomUUID();
      await pool.query(
        `INSERT INTO organization_invitations
         (id, organization_id, email, role, token_hash, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [invitationId, org.rows[0].id, email, role, hashToken(rawToken), expiresAt]
      );

      const baseUrl = String(process.env.PORTAL_BASE_URL || "https://neuralnext-api-neuralnext-inc.up.railway.app").replace(/\/$/, "");
      return reply.code(201).send({
        success: true,
        invitation: {
          id: invitationId,
          email,
          role,
          organization: org.rows[0].name,
          expires_at: expiresAt.toISOString(),
          activation_url: `${baseUrl}/portal/activate?token=${encodeURIComponent(rawToken)}`
        },
        note: "Share this one-time activation link securely. Email delivery is not configured in this milestone."
      });
    } catch (error) {
      request.log.error({ err: error }, "Portal invitation creation failed");
      return reply.code(500).send({ success: false, error: "Could not create invitation" });
    }
  });

  app.post("/api/portal/activate", async (request, reply) => {
    if (!pool) return reply.code(503).send({ success: false, error: "Database unavailable" });
    const token = String(request.body?.token || "");
    const fullName = String(request.body?.full_name || "").trim().slice(0, 200);
    const password = String(request.body?.password || "");
    if (!token || !fullName || password.length < 12) {
      return reply.code(400).send({
        success: false,
        error: "A valid invitation, full name and password of at least 12 characters are required"
      });
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const found = await client.query(
        `SELECT * FROM organization_invitations
         WHERE token_hash=$1 AND accepted_at IS NULL AND revoked_at IS NULL
           AND expires_at > NOW()
         FOR UPDATE`,
        [hashToken(token)]
      );
      if (!found.rowCount) {
        await client.query("ROLLBACK");
        return reply.code(400).send({ success: false, error: "Invitation is invalid, expired or already used" });
      }

      const invitation = found.rows[0];
      let user = await client.query(
        "SELECT id, status FROM users WHERE LOWER(email)=LOWER($1) FOR UPDATE",
        [invitation.email]
      );
      let userId;
      if (user.rowCount) {
        if (user.rows[0].status === "suspended") {
          await client.query("ROLLBACK");
          return reply.code(403).send({ success: false, error: "This account is suspended" });
        }
        userId = user.rows[0].id;
        if (user.rows[0].status === "invited") {
          const passwordHash = await makePasswordHash(password);
          await client.query(
            `UPDATE users SET full_name=$2, password_hash=$3, status='active',
               email_verified_at=COALESCE(email_verified_at,NOW()), updated_at=NOW()
             WHERE id=$1`,
            [userId, fullName, passwordHash]
          );
        }
      } else {
        userId = randomUUID();
        const passwordHash = await makePasswordHash(password);
        await client.query(
          `INSERT INTO users (id,email,full_name,password_hash,status,email_verified_at)
           VALUES ($1,$2,$3,$4,'active',NOW())`,
          [userId, invitation.email, fullName, passwordHash]
        );
      }

      await client.query(
        `INSERT INTO organization_members
         (id, organization_id, user_id, role, status)
         VALUES ($1,$2,$3,$4,'active')
         ON CONFLICT (organization_id,user_id)
         DO UPDATE SET role=EXCLUDED.role,status='active',updated_at=NOW()`,
        [randomUUID(), invitation.organization_id, userId, invitation.role]
      );
      await client.query(
        "UPDATE organization_invitations SET accepted_at=NOW() WHERE id=$1",
        [invitation.id]
      );
      await client.query("COMMIT");
      await createSession(pool, userId, reply);
      return { success: true, message: "Account activated", redirect: "/portal" };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      request.log.error({ err: error }, "Portal account activation failed");
      return reply.code(500).send({ success: false, error: "Could not activate account" });
    } finally {
      client.release();
    }
  });

  app.post("/api/portal/login", async (request, reply) => {
    if (!pool) return reply.code(503).send({ success: false, error: "Database unavailable" });
    const email = String(request.body?.email || "").trim().toLowerCase();
    const password = String(request.body?.password || "");
    const ip = request.ip;
    const attempts = loginAttempts.get(ip) || { count: 0, resetAt: Date.now() + 15 * 60 * 1000 };
    if (attempts.resetAt <= Date.now()) {
      attempts.count = 0;
      attempts.resetAt = Date.now() + 15 * 60 * 1000;
    }
    if (attempts.count >= 10) {
      return reply.code(429).send({ success: false, error: "Too many login attempts. Try again later." });
    }

    try {
      const result = await pool.query(
        "SELECT id, password_hash, status FROM users WHERE LOWER(email)=LOWER($1)",
        [email]
      );
      const valid = result.rowCount && result.rows[0].status === "active"
        && await verifyPassword(password, result.rows[0].password_hash);
      if (!valid) {
        attempts.count += 1;
        loginAttempts.set(ip, attempts);
        return reply.code(401).send({ success: false, error: "Invalid email or password" });
      }
      loginAttempts.delete(ip);
      await createSession(pool, result.rows[0].id, reply);
      await pool.query("UPDATE users SET last_login_at=NOW() WHERE id=$1", [result.rows[0].id]);
      return { success: true };
    } catch (error) {
      request.log.error({ err: error }, "Portal login failed");
      return reply.code(500).send({ success: false, error: "Could not log in" });
    }
  });

  app.get("/api/portal/me", async (request, reply) => {
    if (!pool) return reply.code(503).send({ success: false, error: "Database unavailable" });
    try {
      const context = await getPortalUser(pool, request);
      if (!context) return reply.code(401).send({ success: false, error: "Client login required" });
      return { success: true, ...context };
    } catch (error) {
      request.log.error({ err: error }, "Portal session lookup failed");
      return reply.code(500).send({ success: false, error: "Could not load account" });
    }
  });


  async function requireMembership(request, reply) {
    const context = await getPortalUser(pool, request);
    if (!context) {
      reply.code(401).send({ success: false, error: "Client login required" });
      return null;
    }
    const slug = String(request.query?.organization_slug || request.body?.organization_slug || "").trim();
    if (!slug) {
      reply.code(400).send({ success: false, error: "organization_slug is required" });
      return null;
    }
    const membership = context.memberships.find(item => item.organization_slug === slug);
    if (!membership) {
      reply.code(403).send({ success: false, error: "You do not have access to this organisation" });
      return null;
    }
    return { ...context, membership };
  }

  app.get("/api/portal/content", async (request, reply) => {
    if (!pool) return reply.code(503).send({ success: false, error: "Database unavailable" });
    try {
      const access = await requireMembership(request, reply);
      if (!access) return;
      const result = await pool.query(
        `SELECT a.id, a.request_id, a.status, a.payload, a.submitted_at,
                a.reviewed_at, a.updated_at, a.upload_post_job_id,
                a.upload_post_request_id,
                (a.video_data IS NOT NULL) AS has_video,
                COALESCE(actions.recent_actions, '[]'::json) AS client_actions
         FROM approval_items a
         LEFT JOIN LATERAL (
           SELECT json_agg(json_build_object(
             'action', x.action, 'message', x.message, 'created_at', x.created_at
           ) ORDER BY x.created_at DESC) AS recent_actions
           FROM (
             SELECT action, message, created_at
             FROM client_review_actions
             WHERE approval_item_id = a.id
               AND organization_id = a.organization_id
             ORDER BY created_at DESC LIMIT 5
           ) x
         ) actions ON TRUE
         WHERE a.organization_id = $1 AND a.deleted_at IS NULL
         ORDER BY a.submitted_at DESC
         LIMIT 200`,
        [access.membership.organization_id]
      );
      return {
        success: true,
        organization: access.membership.organization_name,
        role: access.membership.role,
        items: result.rows
      };
    } catch (error) {
      request.log.error({ err: error }, "Tenant-scoped portal content query failed");
      return reply.code(500).send({ success: false, error: "Could not load organisation content" });
    }
  });

  app.get("/api/portal/content/:id/video", async (request, reply) => {
    if (!pool) return reply.code(503).send({ success: false, error: "Database unavailable" });
    try {
      const access = await requireMembership(request, reply);
      if (!access) return;
      const result = await pool.query(
        `SELECT video_data, video_filename, video_mimetype
         FROM approval_items
         WHERE id=$1 AND organization_id=$2
           AND deleted_at IS NULL AND video_data IS NOT NULL`,
        [request.params.id, access.membership.organization_id]
      );
      if (!result.rowCount) return reply.code(404).send({ success: false, error: "Video not found" });
      reply.header("Content-Disposition", 'inline; filename="' + String(result.rows[0].video_filename || "video.mp4").replace(/["\\\\]/g, "") + '"');
      reply.header("Cache-Control", "private, no-store");
      reply.type(result.rows[0].video_mimetype || "video/mp4");
      return reply.send(result.rows[0].video_data);
    } catch (error) {
      request.log.error({ err: error }, "Tenant-scoped video retrieval failed");
      return reply.code(500).send({ success: false, error: "Could not retrieve video" });
    }
  });

  app.post("/api/portal/content/:id/review", async (request, reply) => {
    if (!pool) return reply.code(503).send({ success: false, error: "Database unavailable" });
    try {
      const access = await requireMembership(request, reply);
      if (!access) return;
      if (!["admin", "social_media_manager", "client"].includes(access.membership.role)) {
        return reply.code(403).send({ success: false, error: "Your role cannot review content" });
      }
      const action = String(request.body?.action || "");
      const message = String(request.body?.message || "").trim().slice(0, 2000);
      if (!["approved_by_client", "rejected_by_client", "revision_requested"].includes(action)) {
        return reply.code(400).send({ success: false, error: "Unsupported review action" });
      }
      if (action !== "approved_by_client" && !message) {
        return reply.code(400).send({ success: false, error: "Please include a reason or revision note" });
      }
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const item = await client.query(
          `SELECT id, status FROM approval_items
           WHERE id=$1 AND organization_id=$2 AND deleted_at IS NULL
           FOR UPDATE`,
          [request.params.id, access.membership.organization_id]
        );
        if (!item.rowCount) {
          await client.query("ROLLBACK");
          return reply.code(404).send({ success: false, error: "Content not found" });
        }
        if (item.rows[0].status !== "pending_approval") {
          await client.query("ROLLBACK");
          return reply.code(409).send({ success: false, error: "Only content awaiting approval can be reviewed" });
        }
        const saved = await client.query(
          `INSERT INTO client_review_actions
           (id, approval_item_id, organization_id, user_id, action, message)
           VALUES ($1,$2,$3,$4,$5,$6)
           RETURNING id, action, message, created_at`,
          [randomUUID(), request.params.id, access.membership.organization_id, access.user.id, action, message || null]
        );
        await client.query("COMMIT");
        return reply.code(201).send({
          success: true,
          review: saved.rows[0],
          note: "Decision recorded for Datasignz review. This action does not publish or change the publishing status."
        });
      } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        throw error;
      } finally {
        client.release();
      }
    } catch (error) {
      request.log.error({ err: error }, "Client review action failed");
      return reply.code(500).send({ success: false, error: "Could not record review action" });
    }
  });




  app.get("/api/portal/reviews", async (request, reply) => {
    if (!pool) return reply.code(503).send({ success: false, error: "Database unavailable" });
    try {
      const access = await requireMembership(request, reply);
      if (!access) return;
      const result = await pool.query(
        `SELECT r.id, r.approval_item_id, r.action, r.message, r.created_at,
                u.full_name, u.email
         FROM client_review_actions r
         JOIN users u ON u.id = r.user_id
         WHERE r.organization_id=$1
         ORDER BY r.created_at DESC
         LIMIT 250`,
        [access.membership.organization_id]
      );
      return { success: true, reviews: result.rows };
    } catch (error) {
      request.log.error({ err: error }, "Portal review history query failed");
      return reply.code(500).send({ success: false, error: "Could not load review history" });
    }
  });

  app.get("/api/portal/messages", async (request, reply) => {
    if (!pool) return reply.code(503).send({ success: false, error: "Database unavailable" });
    try {
      const access = await requireMembership(request, reply);
      if (!access) return;
      const itemId = String(request.query?.approval_item_id || "").trim();
      const values = [access.membership.organization_id];
      let itemFilter = "";
      if (itemId) {
        values.push(itemId);
        itemFilter = "AND m.approval_item_id=$2";
      }
      const result = await pool.query(
        `SELECT m.id, m.approval_item_id, m.message, m.created_at,
                u.full_name, u.email
         FROM portal_messages m
         JOIN users u ON u.id=m.user_id
         WHERE m.organization_id=$1 ${itemFilter}
         ORDER BY m.created_at ASC
         LIMIT 500`,
        values
      );
      return { success: true, messages: result.rows };
    } catch (error) {
      request.log.error({ err: error }, "Portal messages query failed");
      return reply.code(500).send({ success: false, error: "Could not load messages" });
    }
  });

  app.post("/api/portal/messages", async (request, reply) => {
    if (!pool) return reply.code(503).send({ success: false, error: "Database unavailable" });
    try {
      const access = await requireMembership(request, reply);
      if (!access) return;
      if (access.membership.role === "guest") return reply.code(403).send({ success: false, error: "Guest access is read-only" });
      const message = String(request.body?.message || "").trim();
      const itemId = request.body?.approval_item_id ? String(request.body.approval_item_id) : null;
      if (!message || message.length > 5000) {
        return reply.code(400).send({ success: false, error: "Message must contain 1 to 5,000 characters" });
      }
      if (itemId) {
        const item = await pool.query(
          "SELECT id FROM approval_items WHERE id=$1 AND organization_id=$2 AND deleted_at IS NULL",
          [itemId, access.membership.organization_id]
        );
        if (!item.rowCount) return reply.code(404).send({ success: false, error: "Related content not found" });
      }
      const saved = await pool.query(
        `INSERT INTO portal_messages (id,organization_id,user_id,approval_item_id,message)
         VALUES ($1,$2,$3,$4,$5)
         RETURNING id,approval_item_id,message,created_at`,
        [randomUUID(), access.membership.organization_id, access.user.id, itemId, message]
      );
      return reply.code(201).send({ success: true, message: saved.rows[0] });
    } catch (error) {
      request.log.error({ err: error }, "Portal message creation failed");
      return reply.code(500).send({ success: false, error: "Could not send message" });
    }
  });

  app.get("/portal/activate", async (request, reply) => {
    const token = String(request.query?.token || "");
    reply.type("text/html; charset=utf-8");
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Activate NeuralNext Engage Account</title>
<style>body{margin:0;background:#0b1020;color:#f3f6fc;font:15px/1.5 system-ui,sans-serif}.panel{max-width:420px;margin:9vh auto;padding:24px;background:#141c30;border:1px solid #2b3953;border-radius:14px}input,button{box-sizing:border-box;width:100%;padding:12px;margin:8px 0 14px;border-radius:8px;border:1px solid #34445f;background:#0e1628;color:#fff;font:inherit}button{background:#7c9cff;color:#081126;border:0;font-weight:700;cursor:pointer}.muted{color:#9aa8c2}.error{color:#ff9292}</style></head><body><main class="panel"><h1>Activate your account</h1><p class="muted">Create your NeuralNext Engage client portal login.</p>
<form id="activate"><label>Your full name</label><input id="name" required maxlength="200"><label>Password (minimum 12 characters)</label><input id="password" type="password" minlength="12" required><label>Confirm password</label><input id="confirm" type="password" minlength="12" required><button>Create account</button></form><p id="result" class="error"></p></main>
<script>const invitationToken=${JSON.stringify(token)};document.getElementById("activate").addEventListener("submit",async function(e){e.preventDefault();const result=document.getElementById("result");const password=document.getElementById("password").value;if(password!==document.getElementById("confirm").value){result.textContent="Passwords do not match.";return;}try{const response=await fetch("/api/portal/activate",{method:"POST",headers:{"Content-Type":"application/json"},credentials:"same-origin",body:JSON.stringify({token:invitationToken,full_name:document.getElementById("name").value,password:password})});const data=await response.json();if(!response.ok)throw new Error(data.error||"Activation failed");window.location.href="/portal";}catch(err){result.textContent=err.message;}});</script></body></html>`;
  });

  app.get("/portal", async (request, reply) => {
    reply.type("text/html; charset=utf-8");
    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NeuralNext Engage | Client Portal</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#141c30;--line:#2b3953;--text:#f3f6fc;--muted:#9aa8c2;--accent:#7c9cff;--green:#39c98a;--red:#ff7272}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 Inter,system-ui,Segoe UI,sans-serif}
.wrap{max-width:1100px;margin:auto;padding:28px 20px}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:24px}
.brand{font-size:22px;font-weight:800}.brand span{color:var(--accent)}.muted{color:var(--muted)}
.panel,.post{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px}
.login{max-width:420px;margin:9vh auto}.login h1{margin-top:0}
input,select,textarea,button{font:inherit}input,select,textarea{width:100%;padding:12px;border:1px solid var(--line);border-radius:9px;background:#0e1628;color:var(--text);margin:7px 0 14px}
button{border:0;border-radius:9px;padding:10px 15px;font-weight:700;cursor:pointer;background:var(--accent);color:#081126}
button.secondary{background:#293650;color:var(--text)}button.good{background:#087c5c;color:white}button.bad{background:#632c36;color:white}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:14px}
.post h3{margin:0 0 8px}.post p{white-space:pre-wrap}.post img,.post video{width:100%;max-height:360px;object-fit:contain;background:#070b14;border-radius:9px;margin-top:10px}
.tag{display:inline-block;padding:3px 9px;border-radius:20px;background:#293650;font-size:12px;margin:2px}
.hidden{display:none}.error{color:#ff9292}.notice{padding:10px 12px;border:1px solid #40546b;border-radius:9px;margin:12px 0;color:#cbd8e8}
@media(max-width:600px){.wrap{padding:18px 12px}.top{align-items:flex-start;flex-direction:column}}
</style></head><body><main class="wrap">
<section id="login" class="panel login"><div class="brand">NeuralNext <span>Engage</span></div>
<h1>Client Portal</h1><p class="muted">Sign in to review your social media content.</p>
<form id="loginForm"><label>Email</label><input id="email" type="email" autocomplete="username" required>
<label>Password</label><input id="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button></form><p id="loginError" class="error"></p></section>
<section id="app" class="hidden">
<header class="top"><div><div class="brand">NeuralNext <span>Engage</span></div><div id="welcome" class="muted"></div></div>
<div class="actions"><select id="orgSelect" aria-label="Organisation"></select><button id="logout" class="secondary">Log out</button></div></header>
<div class="panel"><h2 id="orgTitle">Your content</h2><p class="muted">Review submitted content, request changes or approve it for Datasignz to process.</p><div id="message" class="notice hidden"></div></div>
<div id="content" class="grid" style="margin-top:16px"></div>
<div class="grid" style="margin-top:16px">
  <section class="panel"><h2>Messages</h2><p class="muted">Communication with your Datasignz account team.</p><div id="messages" style="max-height:300px;overflow:auto"></div><form id="messageForm"><label for="messageText">New message</label><textarea id="messageText" rows="3" maxlength="5000" placeholder="Write a message…" required></textarea><button id="sendMessage" type="submit">Send message</button></form></section>
  <section class="panel"><h2>Review history</h2><p class="muted">Recent approvals, rejections and revision requests.</p><div id="reviews"></div></section>
</div>
</section></main>
<script>
(function(){
const login=document.getElementById("login"), app=document.getElementById("app"), content=document.getElementById("content");
const msg=document.getElementById("message"), orgSelect=document.getElementById("orgSelect");
let memberships=[], currentOrg="";
function esc(v){return String(v==null?"":v).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];});}
function showMessage(t){msg.textContent=t;msg.classList.remove("hidden");}
function fail(t){document.getElementById("loginError").textContent=t;}
async function api(url,opts){const res=await fetch(url,Object.assign({credentials:"same-origin",headers:{"Content-Type":"application/json"}},opts||{}));let data={};try{data=await res.json();}catch(e){}if(!res.ok)throw new Error(data.error||"Request failed");return data;}
async function loadExtras(){try{const query="?organization_slug="+encodeURIComponent(currentOrg);const results=await Promise.all([api("/api/portal/messages"+query),api("/api/portal/reviews"+query)]);const messages=results[0].messages||[];const reviews=results[1].reviews||[];document.getElementById("messages").innerHTML=messages.length?messages.map(function(m){return '<div style="padding:9px 0;border-bottom:1px solid var(--line)"><strong>'+esc(m.full_name||m.email)+'</strong><div>'+esc(m.message)+'</div><small class="muted">'+esc(new Date(m.created_at).toLocaleString())+'</small></div>';}).join(""):'<p class="muted">No messages yet.</p>';document.getElementById("reviews").innerHTML=reviews.length?reviews.map(function(r){return '<div style="padding:9px 0;border-bottom:1px solid var(--line)"><strong>'+esc(r.action.replaceAll("_"," "))+'</strong><div>'+esc(r.message||"")+'</div><small class="muted">'+esc(r.full_name||r.email)+' · '+esc(new Date(r.created_at).toLocaleString())+'</small></div>';}).join(""):'<p class="muted">No review activity yet.</p>';const role=memberships.find(function(m){return m.organization_slug===currentOrg;})?.role;document.getElementById("messageForm").classList.toggle("hidden",role==="guest");}catch(e){document.getElementById("messages").innerHTML='<p class="error">'+esc(e.message)+'</p>';}}
async function loadMe(){const data=await api("/api/portal/me");memberships=data.memberships||[];if(!memberships.length)throw new Error("No active organisation membership was found.");document.getElementById("welcome").textContent="Signed in as "+data.user.email;orgSelect.innerHTML=memberships.map(function(m){return '<option value="'+esc(m.organization_slug)+'">'+esc(m.organization_name)+'</option>';}).join("");currentOrg=memberships[0].organization_slug;orgSelect.value=currentOrg;login.classList.add("hidden");app.classList.remove("hidden");await loadContent();}
async function loadContent(){currentOrg=orgSelect.value;await loadExtras();content.innerHTML='<div class="panel">Loading content…</div>';document.getElementById("orgTitle").textContent=memberships.find(function(m){return m.organization_slug===currentOrg;}).organization_name+" content";try{const data=await api("/api/portal/content?organization_slug="+encodeURIComponent(currentOrg));const items=data.items||[];if(!items.length){content.innerHTML='<div class="panel">No content has been submitted for review yet.</div>';return;}content.innerHTML=items.map(function(item){const p=item.payload||{};const media=(p.media_urls||[]).map(function(url){return '<img loading="lazy" src="'+esc(url)+'" alt="Submitted media">';}).join("");const video=item.has_video?'<video controls preload="metadata" src="/api/portal/content/'+encodeURIComponent(item.id)+'/video?organization_slug='+encodeURIComponent(currentOrg)+'"></video>':"";const platforms=(p.platforms||[]).map(function(x){return '<span class="tag">'+esc(x)+'</span>';}).join("");const canReview=item.status==="pending_approval"&&["admin","social_media_manager","client"].includes(memberships.find(function(m){return m.organization_slug===currentOrg;}).role);return '<article class="post"><div><span class="tag">'+esc(item.status)+'</span> '+platforms+'</div><h3>'+esc(p.caption||"Untitled post")+'</h3><p>'+esc(p.caption||"")+'</p><div>'+media+video+'</div><p class="muted">Submitted: '+esc(new Date(item.submitted_at).toLocaleString())+'</p>'+(canReview?'<div class="actions"><button class="good" data-id="'+esc(item.id)+'" data-action="approved_by_client">Approve</button><button class="bad" data-id="'+esc(item.id)+'" data-action="rejected_by_client">Reject</button><button class="secondary" data-id="'+esc(item.id)+'" data-action="revision_requested">Request revision</button></div>':"")+'</article>';}).join("");}catch(e){content.innerHTML='<div class="panel error">'+esc(e.message)+'</div>';}}
document.getElementById("loginForm").addEventListener("submit",async function(e){e.preventDefault();fail("");try{await api("/api/portal/login",{method:"POST",body:JSON.stringify({email:document.getElementById("email").value,password:document.getElementById("password").value})});await loadMe();}catch(err){fail(err.message);}});
orgSelect.addEventListener("change",loadContent);
document.getElementById("messageForm").addEventListener("submit",async function(e){e.preventDefault();const field=document.getElementById("messageText");const button=document.getElementById("sendMessage");const message=field.value.trim();if(!message)return;button.disabled=true;try{await api("/api/portal/messages",{method:"POST",body:JSON.stringify({organization_slug:currentOrg,message:message})});field.value="";await loadExtras();showMessage("Message sent.");}catch(err){showMessage(err.message);}finally{button.disabled=false;}});
document.getElementById("logout").addEventListener("click",async function(){await api("/api/portal/logout",{method:"POST",body:"{}"});app.classList.add("hidden");login.classList.remove("hidden");});
content.addEventListener("click",async function(e){const btn=e.target.closest("button[data-action]");if(!btn)return;let message="";if(btn.dataset.action!=="approved_by_client"){message=window.prompt(btn.dataset.action==="revision_requested"?"Describe the requested changes:":"Please provide a reason for rejecting this content:")||"";if(!message.trim())return;}btn.disabled=true;try{const result=await api("/api/portal/content/"+encodeURIComponent(btn.dataset.id)+"/review?organization_slug="+encodeURIComponent(currentOrg),{method:"POST",body:JSON.stringify({organization_slug:currentOrg,action:btn.dataset.action,message:message})});showMessage(result.note||"Your response was recorded.");await loadContent();}catch(err){showMessage(err.message);btn.disabled=false;}});
loadMe().catch(function(){});
})();
</script></body></html>`;
  });

  app.post("/api/portal/logout", async (request, reply) => {
    if (pool) {
      const token = getCookie(request, portalCookieName);
      if (token) {
        await pool.query(
          "UPDATE user_sessions SET revoked_at=NOW() WHERE token_hash=$1 AND revoked_at IS NULL",
          [hashToken(token)]
        ).catch(error => request.log.warn({ err: error }, "Portal logout session revocation failed"));
      }
    }
    clearSessionCookie(reply);
    return { success: true };
  });
}
