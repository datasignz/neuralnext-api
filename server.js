import Fastify from "fastify";
import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import pg from "pg";

const { Pool } = pg;
const app = Fastify({ logger: true, bodyLimit: 2 * 1024 * 1024 });

const uploadPostBaseUrl = () =>
  (process.env.UPLOAD_POST_API_URL || "https://api.upload-post.com").replace(/\/+$/, "");

const pool = process.env.DATABASE_URL
  ? new Pool({ connectionString: process.env.DATABASE_URL, max: 5 })
  : null;

function secretMatches(provided, expected) {
  if (!provided || !expected) return false;
  const a = Buffer.from(String(provided));
  const b = Buffer.from(String(expected));
  return a.length === b.length && timingSafeEqual(a, b);
}


const dashboardCookieName = "nn_dashboard_session";
const dashboardSessionLifetimeSeconds = 8 * 60 * 60;
const dashboardLoginAttempts = new Map();

function safeStringMatch(provided, expected) {
  if (typeof provided !== "string" || typeof expected !== "string") return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

function dashboardCookieValue(expiresAt) {
  const secret = process.env.DASHBOARD_SESSION_SECRET;
  const signature = createHmac("sha256", secret)
    .update(`neuralnext-dashboard:${expiresAt}`)
    .digest("hex");
  return `${expiresAt}.${signature}`;
}

function hasDashboardSession(request) {
  const secret = process.env.DASHBOARD_SESSION_SECRET;
  if (!secret) return false;
  const cookieHeader = request.headers.cookie || "";
  const cookie = cookieHeader.split(";").map(part => part.trim())
    .find(part => part.startsWith(`${dashboardCookieName}=`));
  if (!cookie) return false;

  const value = decodeURIComponent(cookie.slice(dashboardCookieName.length + 1));
  const [expiryText, suppliedSignature] = value.split(".");
  const expiresAt = Number(expiryText);
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= Math.floor(Date.now() / 1000)) return false;

  const expected = createHmac("sha256", secret)
    .update(`neuralnext-dashboard:${expiresAt}`)
    .digest("hex");
  return safeStringMatch(suppliedSignature || "", expected);
}

function requireReviewAccess(request, reply) {
  if (hasDashboardSession(request)) return true;
  return requireKey(request, reply, "APPROVAL_REVIEW_KEY");
}

function requireKey(request, reply, envName) {
  const expected = process.env[envName];
  const auth = request.headers.authorization || "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const supplied = request.headers["x-api-key"] || bearer;

  if (!expected) {
    reply.code(503).send({
      success: false,
      error: `${envName} is not configured`
    });
    return false;
  }

  if (!secretMatches(supplied, expected)) {
    reply.code(401).send({
      success: false,
      error: "Unauthorized"
    });
    return false;
  }

  return true;
}

function mapUploadPostStatus(data, upstreamOk, isVideo) {
  if (!upstreamOk || data?.success === false) {
    return "failed";
  }

  const statuses = [
    data?.status,
    ...Object.values(data?.results || {}).map(result => result?.status)
  ]
    .filter(Boolean)
    .map(status => String(status).toLowerCase());

  const platformResults = Array.isArray(data?.results)
    ? data.results
    : Object.values(data?.results || {});

  if (
    statuses.includes("failed") ||
    platformResults.some(result => result?.success === false)
  ) {
    return "failed";
  }

  if (statuses.includes("scheduled")) {
    return "scheduled";
  }

  if (statuses.length > 0 && statuses.every(status => status === "completed")) {
    return "published";
  }

  if (
    statuses.includes("processing") ||
    data?.message?.toLowerCase?.().includes("background") ||
    isVideo
  ) {
    return "submitted";
  }

  if (data?.job_id) {
    return "scheduled";
  }

  return "published";
}

function requireDb(reply) {
  if (!pool) {
    reply.code(503).send({
      success: false,
      error: "DATABASE_URL is not configured"
    });
    return false;
  }

  return true;
}

async function initializeDatabase() {
  if (!pool) {
    app.log.warn("DATABASE_URL is not configured; approval endpoints will be unavailable");
    return;
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS approval_items (
      id UUID PRIMARY KEY,
      request_id TEXT UNIQUE NOT NULL,
      status TEXT NOT NULL CHECK (status IN (
        'pending_approval','rejected','publishing','scheduled','submitted','published','failed'
      )),
      payload JSONB NOT NULL,
      submitted_by TEXT,
      reviewed_by TEXT,
      review_note TEXT,
      submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      upload_post_job_id TEXT,
      upload_post_request_id TEXT,
      publish_response JSONB
    )
  `);

  await pool.query(
    "CREATE INDEX IF NOT EXISTS approval_items_status_submitted_idx ON approval_items (status, submitted_at DESC)"
  );
}


const uploadPostPollIntervalMs = Math.max(
  Number(process.env.UPLOAD_POST_POLL_INTERVAL_MS || 60000),
  15000
);
let uploadPostPollRunning = false;

async function pollUploadPostStatuses() {
  if (!pool || !process.env.UPLOAD_POST_API_KEY || uploadPostPollRunning) return;

  uploadPostPollRunning = true;

  try {
    const pending = await pool.query(
      `SELECT id, status, payload, upload_post_job_id, upload_post_request_id
       FROM approval_items
       WHERE status IN ('publishing', 'submitted', 'scheduled')
         AND (upload_post_request_id IS NOT NULL OR upload_post_job_id IS NOT NULL)
       ORDER BY updated_at ASC
       LIMIT 25`
    );

    for (const item of pending.rows) {
      const params = new URLSearchParams();
      if (item.upload_post_request_id) {
        params.set("request_id", item.upload_post_request_id);
      } else if (item.upload_post_job_id) {
        params.set("job_id", item.upload_post_job_id);
      }

      try {
        const response = await fetch(
          `${uploadPostBaseUrl()}/api/uploadposts/status?${params}`,
          {
            headers: {
              Authorization: `Apikey ${process.env.UPLOAD_POST_API_KEY}`
            },
            signal: AbortSignal.timeout(20000)
          }
        );

        const raw = await response.text();
        let data;
        try {
          data = JSON.parse(raw);
        } catch {
          requestLogPollError(item.id, "Upload-Post returned non-JSON status data");
          continue;
        }

        if (!response.ok || data?.success === false) {
          app.log.warn(
            { approvalId: item.id, upstreamStatus: response.status },
            "Background Upload-Post status check was unsuccessful"
          );
          continue;
        }

        const nextStatus = mapUploadPostStatus(
          data,
          true,
          Boolean(item.payload?.video_url)
        );

        if (nextStatus === item.status) continue;

        const updated = await pool.query(
          `UPDATE approval_items
           SET status = $2,
               publish_response = $3::jsonb,
               review_note = $4,
               updated_at = NOW()
           WHERE id = $1
             AND status IN ('publishing', 'submitted', 'scheduled')
           RETURNING id, status`,
          [
            item.id,
            nextStatus,
            JSON.stringify(data),
            nextStatus === "failed"
              ? String(data.error || data.message || "Upload-Post reported a failure").slice(0, 2000)
              : null
          ]
        );

        if (updated.rowCount) {
          app.log.info(
            { approvalId: item.id, previousStatus: item.status, status: nextStatus },
            "Background publishing status synchronised"
          );
        }
      } catch (error) {
        app.log.warn(
          { err: error, approvalId: item.id },
          "Background Upload-Post status check failed"
        );
      }
    }
  } catch (error) {
    app.log.error({ err: error }, "Background status checker failed");
  } finally {
    uploadPostPollRunning = false;
  }
}

function requestLogPollError(approvalId, message) {
  app.log.warn({ approvalId, message }, "Background Upload-Post status response could not be parsed");
}

app.get("/", async () => ({
  name: "NeuralNext Engage API",
  status: "online"
}));

app.get("/health", async () => ({
  status: "ok"
}));



app.get("/dashboard", async (request, reply) => {
  reply.type("text/html; charset=utf-8");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NeuralNext Engage — Dashboard</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#141c30;--line:#27334d;--muted:#9aa8c2;--text:#f3f6fc;--accent:#7c9cff;--green:#39c98a;--red:#ff7272;--amber:#f5bd54}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 Inter,system-ui,Segoe UI,sans-serif}
.wrap{max-width:1180px;margin:auto;padding:28px 22px}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:28px}
.brand{font-size:22px;font-weight:750;letter-spacing:-.5px}.brand span{color:var(--accent)}.muted{color:var(--muted)}
.panel,.stat{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px}
.login{max-width:420px;margin:9vh auto}.login h1{margin:0 0 8px;font-size:25px}
input,button,select{font:inherit}input{width:100%;padding:12px 13px;border:1px solid var(--line);border-radius:9px;background:#0e1628;color:var(--text);margin:7px 0 15px}
button{border:0;border-radius:9px;padding:10px 15px;font-weight:650;cursor:pointer;background:var(--accent);color:#081126}
button.secondary{background:#293650;color:var(--text)}button.danger{background:#522b38;color:#ffdce2}button:disabled{opacity:.5;cursor:wait}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:18px 0 24px}
.stat .num{font-size:28px;font-weight:750}.stat .label{color:var(--muted);font-size:13px}
.section-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:25px 0 12px}
.item{border:1px solid var(--line);border-radius:12px;padding:17px;margin:10px 0;background:#10182a}
.item-top{display:flex;justify-content:space-between;gap:12px;align-items:center}.pill{font-size:12px;padding:4px 9px;border-radius:20px;background:#273650;color:#d9e3fa}
.pill.pending_approval{background:#514122;color:#ffe2a1}.pill.published{background:#164632;color:#a7f0ca}.pill.failed{background:#542b35;color:#ffc1c1}
.caption{white-space:pre-wrap;overflow-wrap:anywhere;margin:12px 0}.meta{font-size:13px;color:var(--muted);display:flex;flex-wrap:wrap;gap:12px}
.actions{display:flex;gap:8px;margin-top:14px;flex-wrap:wrap}.error{color:#ff9a9a;margin-top:10px}.hidden{display:none!important}
#notice{margin:12px 0;color:var(--muted)}a{color:#a9bdff;overflow-wrap:anywhere}
@media(max-width:760px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.wrap{padding:20px 14px}.top{align-items:flex-start}}
</style>
</head>
<body>
<div class="wrap">
<header class="top"><div class="brand">NeuralNext <span>Engage</span></div><button id="logout" class="secondary hidden">Log out</button></header>
<section id="login" class="panel login">
<h1>Dashboard login</h1><p class="muted">Sign in to manage content approvals and publishing.</p>
<form id="loginForm"><label for="username">Username</label><input id="username" autocomplete="username" required>
<label for="password">Password</label><input id="password" type="password" autocomplete="current-password" required>
<button type="submit" id="loginButton">Sign in</button><div id="loginError" class="error"></div></form>
</section>
<main id="app" class="hidden">
<div class="section-head"><div><h1 style="margin:0">Overview</h1><div class="muted">Publishing activity and content approvals</div></div><button id="refresh" class="secondary">Refresh</button></div>
<div class="stats" id="stats"></div>
<div id="notice" role="status"></div>
<div class="section-head"><h2 style="margin:0">Pending approval</h2><span class="muted" id="pendingCount"></span></div>
<div id="queue"></div>
<div class="section-head"><h2 style="margin:0">Recent activity</h2></div>
<div id="recent"></div>
</main>
</div>
<script>
const $=id=>document.getElementById(id);
const labels={pending_approval:"Pending approval",publishing:"Publishing",submitted:"Submitted",scheduled:"Scheduled",published:"Published",failed:"Failed",rejected:"Rejected"};
async function api(path,options={}){const r=await fetch(path,{...options,credentials:"same-origin",headers:{"Content-Type":"application/json",...(options.headers||{})}});let d={};try{d=await r.json()}catch{}if(r.status===401){showLogin();throw new Error("Your session has expired. Please sign in again.")}if(!r.ok)throw new Error(d.error||"Request failed");return d}
function showLogin(){ $("login").classList.remove("hidden");$("app").classList.add("hidden");$("logout").classList.add("hidden");}
function showApp(){ $("login").classList.add("hidden");$("app").classList.remove("hidden");$("logout").classList.remove("hidden");}
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function itemHtml(x,actions=false){
 const p=x.payload||{};const media=[...(p.media_urls||[]),...(p.video_url?[p.video_url]:[])];
 const links=media.map(u=>'<a href="'+esc(u)+'" target="_blank" rel="noopener">Open media</a>').join(" · ");
 const url=x.publish_response?.url||x.publish_response?.post_url||x.publish_response?.results?.instagram?.url||"";
 return '<article class="item"><div class="item-top"><strong>'+esc(p.user||x.submitted_by||"Content item")+'</strong><span class="pill '+esc(x.status)+'">'+esc(labels[x.status]||x.status)+'</span></div>'+
 '<div class="caption">'+esc(p.caption||"(No caption)")+'</div><div class="meta"><span>Platforms: '+esc((p.platforms||[]).join(", ")||"—")+'</span><span>Submitted: '+esc(x.submitted_at?new Date(x.submitted_at).toLocaleString():"—")+'</span></div>'+
 (links?'<div class="meta" style="margin-top:8px">'+links+'</div>':"")+
 (x.review_note?'<p class="error">'+esc(x.review_note)+'</p>':"")+
 (url?'<p><a href="'+esc(url)+'" target="_blank" rel="noopener">View published post</a></p>':"")+
 (actions?'<div class="actions"><button data-action="approve" data-id="'+esc(x.id)+'">Approve &amp; publish</button><button class="danger" data-action="reject" data-id="'+esc(x.id)+'">Reject</button></div>':"")+
 '</article>';
}
async function load(){
 $("notice").textContent="Refreshing dashboard…";
 try{
  const d=await api("/api/dashboard/overview");
  const totals=d.totals||{};
  $("stats").innerHTML=Object.entries(labels).map(([k,v])=>'<div class="stat"><div class="num">'+(totals[k]||0)+'</div><div class="label">'+v+'</div></div>').join("");
  const pending=(d.items||[]).filter(x=>x.status==="pending_approval");
  $("pendingCount").textContent=pending.length+" items";
  $("queue").innerHTML=pending.length?pending.map(x=>itemHtml(x,true)).join(""):'<div class="panel muted">No items waiting for approval.</div>';
  $("recent").innerHTML=(d.items||[]).length?d.items.map(x=>itemHtml(x,false)).join(""):'<div class="panel muted">No activity yet.</div>';
  $("notice").textContent="Last updated: "+new Date(d.generated_at).toLocaleString();
 }catch(e){$("notice").textContent=e.message}
}
$("loginForm").addEventListener("submit",async e=>{e.preventDefault();$("loginButton").disabled=true;$("loginError").textContent="";
 try{await api("/api/dashboard/login",{method:"POST",body:JSON.stringify({username:$("username").value,password:$("password").value})});$("password").value="";showApp();await load()}
 catch(err){$("loginError").textContent=err.message}finally{$("loginButton").disabled=false}});
$("logout").addEventListener("click",async()=>{try{await api("/api/dashboard/logout",{method:"POST",body:"{}"})}finally{showLogin()}});
$("refresh").addEventListener("click",load);
$("queue").addEventListener("click",async e=>{const b=e.target.closest("button[data-action]");if(!b)return;const action=b.dataset.action;const id=b.dataset.id;
 if(action==="reject"&&!confirm("Reject this content item?"))return;
 if(action==="approve"&&!confirm("Approve and publish this content now?"))return;
 b.disabled=true;$("notice").textContent=action==="approve"?"Publishing…":"Rejecting…";
 try{await api("/api/approval/"+encodeURIComponent(id)+"/"+action,{method:"POST",body:JSON.stringify({reviewed_by:"dashboard"})});await load()}
 catch(err){$("notice").textContent=err.message;b.disabled=false}
});
(async()=>{try{await api("/api/dashboard/me");showApp();await load()}catch{showLogin()}})();
setInterval(()=>{if(!$("app").classList.contains("hidden"))load()},60000);
</script>
</body></html>`;
});

// Dashboard login. Credentials and signing secret are configured in Railway variables.
app.post("/api/dashboard/login", async (request, reply) => {
  const username = process.env.DASHBOARD_USERNAME;
  const password = process.env.DASHBOARD_PASSWORD;
  const signingSecret = process.env.DASHBOARD_SESSION_SECRET;

  if (!username || !password || !signingSecret) {
    return reply.code(503).send({
      success: false,
      error: "Dashboard login is not configured"
    });
  }

  const ip = request.ip;
  const now = Date.now();
  const attempt = dashboardLoginAttempts.get(ip) || { count: 0, firstAt: now };
  if (now - attempt.firstAt > 15 * 60 * 1000) {
    dashboardLoginAttempts.delete(ip);
  } else if (attempt.count >= 10) {
    return reply.code(429).send({ success: false, error: "Too many login attempts. Try again in 15 minutes." });
  }

  const suppliedUsername = String(request.body?.username || "");
  const suppliedPassword = String(request.body?.password || "");
  const valid = safeStringMatch(suppliedUsername, username) &&
    safeStringMatch(suppliedPassword, password);

  if (!valid) {
    dashboardLoginAttempts.set(ip, {
      count: attempt.count + 1,
      firstAt: attempt.firstAt
    });
    return reply.code(401).send({ success: false, error: "Invalid username or password" });
  }

  dashboardLoginAttempts.delete(ip);
  const expiresAt = Math.floor(Date.now() / 1000) + dashboardSessionLifetimeSeconds;
  reply.header(
    "Set-Cookie",
    `${dashboardCookieName}=${dashboardCookieValue(expiresAt)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${dashboardSessionLifetimeSeconds}`
  );
  return { success: true, expires_at: new Date(expiresAt * 1000).toISOString() };
});

app.get("/api/dashboard/me", async (request, reply) => {
  if (!hasDashboardSession(request)) {
    return reply.code(401).send({ success: false, error: "Not authenticated" });
  }
  return { success: true, authenticated: true };
});

app.post("/api/dashboard/logout", async (request, reply) => {
  reply.header(
    "Set-Cookie",
    `${dashboardCookieName}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
  );
  return { success: true };
});

// Upload-Post status check with automatic PostgreSQL synchronisation.
app.get("/api/uploadposts/status", async (request, reply) => {
  if (!requireReviewAccess(request, reply)) return;
  if (!requireDb(reply)) return;

  const apiKey = process.env.UPLOAD_POST_API_KEY;

  if (!apiKey) {
    return reply.code(500).send({
      success: false,
      error: "UPLOAD_POST_API_KEY is not configured"
    });
  }

  const {
    request_id: requestId,
    job_id: jobId
  } = request.query || {};

  if (!requestId && !jobId) {
    return reply.code(400).send({
      success: false,
      error: "Provide request_id or job_id"
    });
  }

  const params = new URLSearchParams();

  if (requestId) params.set("request_id", String(requestId));
  if (jobId) params.set("job_id", String(jobId));

  try {
    const response = await fetch(
      `${uploadPostBaseUrl()}/api/uploadposts/status?${params}`,
      {
        headers: {
          Authorization: `Apikey ${apiKey}`
        },
        signal: AbortSignal.timeout(30_000)
      }
    );

    const text = await response.text();

    let data;

    try {
      data = JSON.parse(text);
    } catch {
      data = {
        success: false,
        error: text
      };
    }

    if (!response.ok) {
      return reply.code(response.status).send(data);
    }

    // Match this Upload-Post job to its approval record.
    const matching = await pool.query(
      `SELECT id, status, payload
       FROM approval_items
       WHERE ($1::text IS NOT NULL AND upload_post_request_id = $1)
          OR ($2::text IS NOT NULL AND upload_post_job_id = $2)
       ORDER BY updated_at DESC
       LIMIT 1`,
      [
        requestId ? String(requestId) : null,
        jobId ? String(jobId) : null
      ]
    );

    let sync = {
      matched: false,
      updated: false
    };

    if (matching.rowCount > 0) {
      const item = matching.rows[0];
      const isVideo = Boolean(item.payload?.video_url);

      const nextStatus = mapUploadPostStatus(
        data,
        true,
        isVideo
      );

      // Only update records that are still awaiting final status.
      const updated = await pool.query(
        `UPDATE approval_items
         SET status = $2,
             publish_response = $3::jsonb,
             review_note = $4,
             updated_at = NOW()
         WHERE id = $1
           AND status IN ('publishing', 'submitted', 'scheduled')
         RETURNING id, status, updated_at`,
        [
          item.id,
          nextStatus,
          JSON.stringify(data),
          nextStatus === "failed"
            ? String(
                data.error ||
                data.message ||
                "Upload-Post reported a failure"
              ).slice(0, 2000)
            : null
        ]
      );

      sync = {
        matched: true,
        updated: updated.rowCount > 0,
        approval_id: item.id,
        status: updated.rows[0]?.status || item.status,
        upload_post_status: data.status || null
      };

      request.log.info(
        sync,
        "Approval status synchronised from Upload-Post"
      );
    }

    return reply.send({
      ...data,
      neuralnext_sync: sync
    });

  } catch (error) {
    request.log.error(
      { err: error },
      "Upload-Post status request failed"
    );

    return reply.code(502).send({
      success: false,
      error: "Could not retrieve or synchronise publishing status"
    });
  }
});

// Submit metadata and public HTTPS media URLs for human review.
// This route never publishes.
app.post("/api/approval/submit", async (request, reply) => {
  if (!requireKey(request, reply, "APPROVAL_SUBMIT_KEY")) return;
  if (!requireDb(reply)) return;

  const body = request.body || {};

  const platforms = Array.isArray(body.platforms)
    ? body.platforms
    : [];

  const mediaUrls = Array.isArray(body.media_urls)
    ? body.media_urls.map((url) => {
        const value = String(url).trim();
        const markdownMatch = value.match(
          /^\[(https?:\/\/[^\]]+)\]\((https?:\/\/[^)]+)\)$/
        );

        return markdownMatch ? markdownMatch[2] : value;
      })
    : [];

  request.log.info({
    receivedMediaUrls: body.media_urls,
    cleanedMediaUrls: mediaUrls
  }, "Approval media URL normalization");

  const videoUrl = body.video_url;

  if (typeof body.user !== "string" || !body.user.trim()) {
    return reply.code(400).send({
      success: false,
      error: "user is required"
    });
  }

  if (!platforms.length || platforms.some(p => typeof p !== "string" || !p.trim())) {
    return reply.code(400).send({
      success: false,
      error: "platforms must be a non-empty array of platform names"
    });
  }

  if ((mediaUrls.length === 0) === !videoUrl) {
    return reply.code(400).send({
      success: false,
      error: "Provide either media_urls (photo URLs) or video_url, but not both"
    });
  }

  if (mediaUrls.length > 20) {
    return reply.code(400).send({
      success: false,
      error: "A maximum of 20 photo URLs is supported"
    });
  }

  const urls = videoUrl ? [videoUrl] : mediaUrls;

  if (urls.some(value => {
    try {
      const u = new URL(value);
      return u.protocol !== "https:";
    } catch {
      return true;
    }
  })) {
    return reply.code(400).send({
      success: false,
      error: "Media must use valid public HTTPS URLs"
    });
  }

  if (body.scheduled_date && Number.isNaN(Date.parse(body.scheduled_date))) {
    return reply.code(400).send({
      success: false,
      error: "scheduled_date must be a valid ISO-8601 date/time"
    });
  }

  const requestId = String(body.request_id || randomUUID()).slice(0, 200);
  const id = randomUUID();

  const payload = {
    user: body.user.trim(),
    platforms,
    caption: String(body.caption || ""),
    media_urls: videoUrl ? [] : mediaUrls,
    video_url: videoUrl || null,
    scheduled_date: body.scheduled_date || null,
    timezone: body.timezone || "America/Paramaribo",
    extra_fields:
      body.extra_fields &&
      typeof body.extra_fields === "object" &&
      !Array.isArray(body.extra_fields)
        ? body.extra_fields
        : {}
  };

  request.log.info({
    payloadMediaUrls: payload.media_urls,
    databaseRequestId: requestId
  }, "Approval payload before database insert");

  try {
    const result = await pool.query(
      `INSERT INTO approval_items (id, request_id, status, payload, submitted_by)
       VALUES ($1, $2, 'pending_approval', $3::jsonb, $4)
       ON CONFLICT (request_id) DO NOTHING
       RETURNING id, request_id, status, submitted_at, payload`,
      [
        id,
        requestId,
        JSON.stringify(payload),
        String(body.submitted_by || "agent").slice(0, 200)
      ]
    );

    request.log.info({
      insertedId: result.rows[0]?.id,
      insertedRequestId: result.rows[0]?.request_id,
      insertedMediaUrls: result.rows[0]?.payload?.media_urls
    }, "Approval database insert read-back");

    if (result.rowCount === 0) {
      const existing = await pool.query(
        "SELECT id, request_id, status, submitted_at FROM approval_items WHERE request_id=$1",
        [requestId]
      );

      return reply.code(200).send({
        success: true,
        duplicate: true,
        item: existing.rows[0]
      });
    }

    return reply.code(201).send({
      success: true,
      item: result.rows[0]
    });

  } catch (error) {
    request.log.error(
      { err: error },
      "Approval submission failed"
    );

    return reply.code(500).send({
      success: false,
      error: "Could not save approval request"
    });
  }
});


// Dashboard overview: status counts and latest approval/publication records.
app.get("/api/dashboard/overview", async (request, reply) => {
  if (!requireReviewAccess(request, reply)) return;
  if (!requireDb(reply)) return;

  try {
    const counts = await pool.query(
      `SELECT status, COUNT(*)::int AS count
       FROM approval_items
       GROUP BY status`
    );

    const recent = await pool.query(
      `SELECT id, request_id, status, payload, submitted_by,
              reviewed_by, review_note, submitted_at, reviewed_at,
              updated_at, upload_post_job_id, upload_post_request_id,
              publish_response
       FROM approval_items
       ORDER BY submitted_at DESC
       LIMIT 50`
    );

    const summary = {
      pending_approval: 0,
      publishing: 0,
      submitted: 0,
      scheduled: 0,
      published: 0,
      failed: 0,
      rejected: 0
    };

    for (const row of counts.rows) {
      summary[row.status] = row.count;
    }

    return {
      success: true,
      generated_at: new Date().toISOString(),
      totals: summary,
      total_items: Object.values(summary).reduce((sum, value) => sum + value, 0),
      items: recent.rows
    };
  } catch (error) {
    request.log.error({ err: error }, "Dashboard overview query failed");
    return reply.code(500).send({
      success: false,
      error: "Could not load dashboard overview"
    });
  }
});

// List pending approval requests.
app.get("/api/approval/pending", async (request, reply) => {
  if (!requireReviewAccess(request, reply)) return;
  if (!requireDb(reply)) return;

  try {
    const limit = Math.min(
      Math.max(Number(request.query?.limit) || 50, 1),
      100
    );

    const result = await pool.query(
      `SELECT id, request_id, status, payload, submitted_by, submitted_at
       FROM approval_items
       WHERE status='pending_approval'
       ORDER BY submitted_at ASC
       LIMIT $1`,
      [limit]
    );

    request.log.info({
      pendingRecords: result.rows.map(row => ({
        id: row.id,
        requestId: row.request_id,
        mediaUrls: row.payload?.media_urls
      }))
    }, "Pending endpoint database read-back");

    return {
      success: true,
      items: result.rows
    };

  } catch (error) {
    request.log.error(
      { err: error },
      "Pending approval list failed"
    );

    return reply.code(500).send({
      success: false,
      error: "Could not list pending approvals"
    });
  }
});

// Retrieve the status of an approval record.
app.get("/api/approval/:id/status", async (request, reply) => {
  if (!requireReviewAccess(request, reply)) return;
  if (!requireDb(reply)) return;

  try {
    const result = await pool.query(
      `SELECT id, request_id, status, reviewed_by, review_note,
              submitted_at, reviewed_at, updated_at,
              upload_post_job_id, upload_post_request_id,
              publish_response
       FROM approval_items
       WHERE id=$1`,
      [request.params.id]
    );

    if (!result.rowCount) {
      return reply.code(404).send({
        success: false,
        error: "Approval item not found"
      });
    }

    return {
      success: true,
      item: result.rows[0]
    };

  } catch (error) {
    if (error.code === "22P02") {
      return reply.code(400).send({
        success: false,
        error: "Invalid approval ID"
      });
    }

    request.log.error(
      { err: error },
      "Approval status lookup failed"
    );

    return reply.code(500).send({
      success: false,
      error: "Could not retrieve approval status"
    });
  }
});

// Reject an approval request.
app.post("/api/approval/:id/reject", async (request, reply) => {
  if (!requireReviewAccess(request, reply)) return;
  if (!requireDb(reply)) return;

  const note = String(request.body?.reason || "").slice(0, 2000);
  const reviewer = String(request.body?.reviewed_by || "reviewer").slice(0, 200);

  try {
    const result = await pool.query(
      `UPDATE approval_items
       SET status='rejected',
           reviewed_by=$2,
           review_note=$3,
           reviewed_at=NOW(),
           updated_at=NOW()
       WHERE id=$1 AND status='pending_approval'
       RETURNING id, request_id, status, reviewed_by, review_note, reviewed_at`,
      [request.params.id, reviewer, note]
    );

    if (!result.rowCount) {
      return reply.code(409).send({
        success: false,
        error: "Item not found or no longer pending approval"
      });
    }

    return {
      success: true,
      item: result.rows[0]
    };

  } catch (error) {
    if (error.code === "22P02") {
      return reply.code(400).send({
        success: false,
        error: "Invalid approval ID"
      });
    }

    request.log.error(
      { err: error },
      "Approval rejection failed"
    );

    return reply.code(500).send({
      success: false,
      error: "Could not reject approval item"
    });
  }
});

// Approve and publish a request through Upload-Post.
app.post("/api/approval/:id/approve", async (request, reply) => {
  if (!requireReviewAccess(request, reply)) return;
  if (!requireDb(reply)) return;

  const client = await pool.connect();
  let item;

  try {
    await client.query("BEGIN");

    const selected = await client.query(
      "SELECT * FROM approval_items WHERE id=$1 FOR UPDATE",
      [request.params.id]
    );

    if (!selected.rowCount) {
      await client.query("ROLLBACK");

      return reply.code(404).send({
        success: false,
        error: "Approval item not found"
      });
    }

    item = selected.rows[0];

    if (item.status !== "pending_approval") {
      await client.query("ROLLBACK");

      return reply.code(409).send({
        success: false,
        error: "Item is not pending approval",
        status: item.status
      });
    }

    await client.query(
      `UPDATE approval_items
       SET status='publishing',
           reviewed_by=$2,
           reviewed_at=NOW(),
           updated_at=NOW()
       WHERE id=$1`,
      [
        item.id,
        String(request.body?.reviewed_by || "reviewer").slice(0, 200)
      ]
    );

    await client.query("COMMIT");

  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});

    if (error.code === "22P02") {
      return reply.code(400).send({
        success: false,
        error: "Invalid approval ID"
      });
    }

    request.log.error(
      { err: error },
      "Could not lock approval item"
    );

    return reply.code(500).send({
      success: false,
      error: "Could not begin approval"
    });

  } finally {
    client.release();
  }

  const apiKey = process.env.UPLOAD_POST_API_KEY;

  if (!apiKey) {
    await pool.query(
      `UPDATE approval_items
       SET status='failed',
           review_note='UPLOAD_POST_API_KEY is not configured',
           updated_at=NOW()
       WHERE id=$1`,
      [item.id]
    );

    return reply.code(503).send({
      success: false,
      error: "UPLOAD_POST_API_KEY is not configured"
    });
  }

  const payload = item.payload;
  const isVideo = Boolean(payload.video_url);

  const form = new FormData();

  form.set("user", payload.user);

  for (const platform of payload.platforms) {
    form.append("platform[]", platform);
  }

  if (payload.caption) {
    form.set("title", payload.caption);
  }

  if (isVideo) {
    form.set("video", payload.video_url);
  } else {
    for (const url of payload.media_urls) {
      form.append("photos[]", url);
    }
  }

  if (payload.scheduled_date) {
    form.set("scheduled_date", payload.scheduled_date);
    form.set("timezone", payload.timezone || "America/Paramaribo");
  }

  form.set("request_id", `approval-${item.id}`);
  form.set("external_id", item.id);

  if (isVideo) {
    form.set("async_upload", "true");
  }

  for (const [key, value] of Object.entries(payload.extra_fields || {})) {
    if ([
      "user",
      "platform[]",
      "photos[]",
      "video",
      "request_id",
      "scheduled_date",
      "timezone",
      "external_id"
    ].includes(key)) {
      continue;
    }

    if (Array.isArray(value)) {
      for (const v of value) {
        form.append(key, String(v));
      }
    } else if (value !== null && value !== undefined) {
      form.set(key, String(value));
    }
  }

  try {
    const endpoint = isVideo
      ? "/api/upload"
      : "/api/upload_photos";

    const upstream = await fetch(
      `${uploadPostBaseUrl()}${endpoint}`,
      {
        method: "POST",
        headers: {
          Authorization: `Apikey ${apiKey}`,
          "Idempotency-Key": `approval-${item.id}`
        },
        body: form,
        signal: AbortSignal.timeout(10 * 60 * 1000)
      }
    );

    const raw = await upstream.text();

    let data;

    try {
      data = JSON.parse(raw);
    } catch {
      data = {
        success: false,
        error: raw
      };
    }

    const success = upstream.ok && data?.success !== false;

    const nextStatus = mapUploadPostStatus(
      data,
      upstream.ok,
      isVideo
    );

    await pool.query(
      `UPDATE approval_items
       SET status=$2,
           upload_post_job_id=$3,
           upload_post_request_id=$4,
           publish_response=$5::jsonb,
           review_note=$6,
           updated_at=NOW()
       WHERE id=$1`,
      [
        item.id,
        nextStatus,
        data.job_id || null,
        data.request_id || `approval-${item.id}`,
        JSON.stringify(data),
        success
          ? null
          : String(
              data.error ||
              data.message ||
              "Upload-Post request failed"
            ).slice(0, 2000)
      ]
    );

    return reply.code(
      success ? 200 : (upstream.status >= 400 ? upstream.status : 502)
    ).send({
      success,
      approval_id: item.id,
      status: nextStatus,
      upload_post: data
    });

  } catch (error) {
    request.log.error(
      { err: error, approvalId: item.id },
      "Approved publishing request failed"
    );

    await pool.query(
      `UPDATE approval_items
       SET status='failed',
           review_note=$2,
           updated_at=NOW()
       WHERE id=$1`,
      [
        item.id,
        String(error.message || "Publishing request failed").slice(0, 2000)
      ]
    );

    return reply.code(502).send({
      success: false,
      approval_id: item.id,
      status: "failed",
      error: "Publishing request failed; check status before retrying"
    });
  }
});

// Direct publishing is disabled.
// All new content must pass through human approval.
app.post("/api/social/publish", async (request, reply) => {
  return reply.code(403).send({
    success: false,
    error: "Direct publishing is disabled. Submit content to /api/approval/submit and publish only after human approval."
  });
});

const port = Number(process.env.PORT || 3000);

try {
  await initializeDatabase();
  await app.listen({
    port,
    host: "0.0.0.0"
  });

  app.log.info(`NeuralNext API running on port ${port}`);
  // Start periodic status checks after the API is listening.
  const uploadPostPollTimer = setInterval(
    pollUploadPostStatuses,
    uploadPostPollIntervalMs
  );
  uploadPostPollTimer.unref();
  pollUploadPostStatuses();

} catch (error) {
  app.log.error(error);
  process.exit(1);
}
