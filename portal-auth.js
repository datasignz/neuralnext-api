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
