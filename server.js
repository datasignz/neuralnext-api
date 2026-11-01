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
const guestCookieName = "nn_guest_session";
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

function hasGuestSession(request) {
  const secret = process.env.DASHBOARD_SESSION_SECRET;
  if (!secret) return false;
  const cookieHeader = request.headers.cookie || "";
  const cookie = cookieHeader.split(";").map(part => part.trim())
    .find(part => part.startsWith(`${guestCookieName}=`));
  if (!cookie) return false;
  const value = decodeURIComponent(cookie.slice(guestCookieName.length + 1));
  const [expiryText, suppliedSignature] = value.split(".");
  const expiresAt = Number(expiryText);
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= Math.floor(Date.now() / 1000)) return false;
  const expected = createHmac("sha256", secret)
    .update(`neuralnext-guest:${expiresAt}`)
    .digest("hex");
  return safeStringMatch(suppliedSignature || "", expected);
}

function requireDashboardReadAccess(request, reply) {
  if (hasDashboardSession(request) || hasGuestSession(request)) return true;
  return requireKey(request, reply, "APPROVAL_REVIEW_KEY");
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
<title>NeuralNext Engage - Dashboard</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#141c30;--line:#27334d;--muted:#9aa8c2;--text:#f3f6fc;--accent:#7c9cff;--green:#39c98a;--red:#ff7272;--amber:#f5bd54}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 Inter,system-ui,Segoe UI,sans-serif}
.wrap{max-width:1180px;margin:auto;padding:28px 22px}.dashboard-banner{width:100%;margin:0 0 22px;border:1px solid var(--line);border-radius:14px;overflow:hidden;background:#080d18}.dashboard-banner img{display:block;width:100%;height:clamp(150px,22vw,280px);object-fit:cover;object-position:center top}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:28px}
.brand{font-size:22px;font-weight:750;letter-spacing:-.5px}.brand span{color:var(--accent)}.muted{color:var(--muted)}.guest-note{padding:10px 13px;border:1px solid #49617e;border-radius:9px;background:#14243a;color:#c9dcf5;margin:12px 0 18px}
.panel,.stat{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px}
.login{max-width:420px;margin:9vh auto}.login h1{margin:0 0 8px;font-size:25px}
input,button,select{font:inherit}select{padding:10px 36px 10px 12px;border:1px solid #40546b;border-radius:9px;background:#172438;color:var(--text);min-width:240px}input{width:100%;padding:12px 13px;border:1px solid var(--line);border-radius:9px;background:#0e1628;color:var(--text);margin:7px 0 15px}
button{border:0;border-radius:9px;padding:10px 15px;font-weight:650;cursor:pointer;background:var(--accent);color:#081126}
button.secondary{background:#293650;color:var(--text)}button.danger{background:#522b38;color:#ffdce2}button:disabled{opacity:.5;cursor:wait}
.stats{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:14px;margin:18px 0 24px}
.stat{display:flex;align-items:center;gap:14px;min-height:96px;padding:16px 18px;border-radius:13px;background:linear-gradient(135deg,#1b2940,#182337);border:1px solid #315078;position:relative}
.stat:after{content:"›";margin-left:auto;color:#b9c8da;font-size:28px}.stat .stat-icon{width:38px;height:38px;flex:0 0 38px;display:grid;place-items:center}.stat .stat-icon svg{width:36px;height:36px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}.stat .stat-icon svg .dot{fill:currentColor;stroke:none}.stat .num{font-size:30px;font-weight:780;line-height:1.05}.stat .label{color:#e1e8f4;font-size:14px;white-space:nowrap}
.stat.pending_approval{background:linear-gradient(135deg,#3a2c50,#29233d);border-color:#9c65d5}.stat.pending_approval .stat-icon{color:#c58aff}.stat.publishing{border-color:#2879bd}.stat.publishing .stat-icon{color:#57b8ef}.stat.scheduled{border-color:#168db0}.stat.scheduled .stat-icon{color:#53d9f1}.stat.published{background:linear-gradient(135deg,#123e39,#173b38);border-color:#169d76}.stat.published .stat-icon{color:#42d9a0}.stat.failed{background:linear-gradient(135deg,#49252d,#38242c);border-color:#c23c48}.stat.failed .stat-icon{color:#ff6565}.stat.rejected{border-color:#586879}.stat.rejected .stat-icon{color:#b9c5d3}
.section-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:25px 0 12px}
.dashboard-columns{display:grid;grid-template-columns:minmax(0,1.9fr) minmax(330px,1fr);gap:22px;align-items:start}.dashboard-panel{background:linear-gradient(145deg,#182435,#121c2b);border:1px solid #34465c;border-radius:13px;overflow:hidden;min-width:0}.dashboard-panel-head{display:flex;align-items:center;gap:14px;padding:14px 20px;border-bottom:1px solid #34465c}.dashboard-panel-head .head-icon{width:28px;height:28px;flex:0 0 28px;color:#dbe7f4}.dashboard-panel-head .head-icon svg{width:28px;height:28px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}.dashboard-panel-head h2{font-size:17px;margin:0;font-weight:750}.dashboard-panel-head p{margin:0;color:#c0cada;font-size:13px}.dashboard-panel-body{padding:0 14px 14px}
.item{border:1px solid #34465c;border-radius:12px;padding:17px;margin:10px 0;background:linear-gradient(145deg,#1c293a,#172333)}
.approval-card{display:grid;grid-template-columns:minmax(180px,28%) minmax(0,1fr);gap:18px}.approval-media .media-preview{margin:0}.approval-media .media-preview img{width:100%;height:175px;max-height:210px;object-fit:cover}.approval-media .media-preview video{width:100%;max-height:210px}.approval-content{min-width:0}.approval-content .item-top{justify-content:flex-start;flex-wrap:wrap;margin-bottom:10px}.approval-content .submitted{margin-left:auto;color:#bdc9d8;font-size:12px}.platform-tag{background:#29394d;border:1px solid #40546b;border-radius:9px;padding:3px 9px;font-size:12px}.caption-editor{min-height:78px;background:#111b2b;border-color:#8291a3}.actions button{padding:9px 13px}.actions button:not(.secondary):not(.danger){background:#087c5c;color:white;border:1px solid #1bb88b}.actions .danger{background:#632c36;color:#fff;border:1px solid #d54a55}.actions .secondary{background:#2a3c52;color:#fff;border:1px solid #7890a8}
.activity-list{padding-top:4px}.activity-row{display:flex;align-items:center;gap:10px;min-height:51px;border-bottom:1px solid #34465c;font-size:12px}.activity-status{min-width:84px;text-align:center;padding:4px 7px;border-radius:18px;background:#26384b;color:#e6edf5}.activity-status.published{background:#15533f;color:#c4f5df;border:1px solid #258a67}.activity-status.rejected,.activity-status.failed{background:#512b34;color:#ffd7dc;border:1px solid #8d3b49}.social-icon{width:23px;height:23px;display:grid;place-items:center;border-radius:50%;font-weight:800;font-size:17px;flex:0 0 23px}.social-icon.instagram{background:linear-gradient(135deg,#6c39c6,#f04478,#ffad47);color:white}.social-icon.facebook{background:#1877f2;color:white;font-family:Arial}.social-icon.other{background:#40546b;color:white}.activity-title{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.activity-row time{white-space:nowrap;color:#c1ccda}.activity-link{color:#d8e4f3;font-size:17px;text-decoration:none}
.client-controls{display:flex;align-items:center;gap:10px}.client-controls label{color:var(--muted);font-size:13px}@media(max-width:1050px){.stats{grid-template-columns:repeat(3,minmax(0,1fr))}.dashboard-columns{grid-template-columns:1fr}}
@media(max-width:760px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.wrap{padding:20px 14px}.top{align-items:flex-start}.approval-card{grid-template-columns:1fr}.approval-media .media-preview img{height:auto;max-height:260px}.activity-row{gap:7px}.activity-row time{display:none}.activity-status{min-width:74px}}
.item-top{display:flex;justify-content:space-between;gap:12px;align-items:center}.pill{font-size:12px;padding:4px 9px;border-radius:20px;background:#273650;color:#d9e3fa}
.pill.pending_approval{background:#514122;color:#ffe2a1}.pill.published{background:#164632;color:#a7f0ca}.pill.failed{background:#542b35;color:#ffc1c1}
.media-preview{margin:14px 0;display:flex;gap:9px;align-items:flex-start;flex-wrap:wrap}.media-preview img{display:block;max-width:100%;width:auto;max-height:320px;object-fit:contain;border-radius:9px;background:#080d18}.media-preview.multi img{width:clamp(130px,28vw,230px);height:190px;object-fit:cover}.media-preview video{display:block;width:min(100%,620px);max-height:380px;background:#05070c;border-radius:9px}.media-empty{color:var(--muted);font-size:13px;margin:12px 0}.caption-label{display:block;color:var(--muted);font-size:13px;margin:14px 0 5px}.caption-editor{display:block;width:100%;min-height:110px;resize:vertical;padding:12px;border:1px solid var(--line);border-radius:9px;background:#0e1628;color:var(--text);font:inherit;line-height:1.5}.original-caption{margin:8px 0;color:var(--muted);font-size:13px}.original-caption div{white-space:pre-wrap;margin-top:7px}.rejection-editor{margin-top:12px;padding:12px;border:1px solid var(--line);border-radius:10px;background:#0c1425}.rejection-editor label{display:block;color:var(--muted);font-size:13px;margin-bottom:6px}.rejection-editor textarea{display:block;width:100%;min-height:85px;resize:vertical;padding:10px;border:1px solid var(--line);border-radius:8px;background:#101a2e;color:var(--text);font:inherit}.caption{white-space:pre-wrap;overflow-wrap:anywhere;margin:12px 0}.meta{font-size:13px;color:var(--muted);display:flex;flex-wrap:wrap;gap:12px}
.actions{display:flex;gap:8px;margin-top:14px;flex-wrap:wrap}.error{color:#ff9a9a;margin-top:10px}.hidden{display:none!important}
#notice{margin:12px 0;color:var(--muted)}a{color:#a9bdff;overflow-wrap:anywhere}
@media(max-width:760px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.wrap{padding:20px 14px}.top{align-items:flex-start}}
</style>
</head>
<body>
<div class="wrap">
<div class="dashboard-banner"><img src="https://raw.githubusercontent.com/datasignz/neuralnext-api/main/neuralnext-banner.jpg" alt="NeuralNext global connectivity banner"></div>
<header class="top"><div class="brand">NeuralNext <span>Engage</span> - Dashboard</div><button id="logout" class="secondary hidden">Log out</button></header>
<section id="login" class="panel login">
<h1>Dashboard login</h1><p class="muted">Sign in to manage content approvals and publishing.</p>
<form id="loginForm"><label for="username">Username</label><input id="username" autocomplete="username" required>
<label for="password">Password</label><input id="password" type="password" autocomplete="current-password" required>
<button type="submit" id="loginButton">Sign in</button><button type="button" id="guestButton" class="secondary" style="margin-left:8px">Continue as guest</button><div id="loginError" class="error"></div></form>
</section>
<main id="app" class="hidden">
<div id="guestNote" class="guest-note hidden">Guest view: you can browse dashboard content, but approving, rejecting and saving changes are disabled.</div>
<div class="section-head dashboard-toolbar"><div><h1 style="margin:0">Overview</h1><div class="muted">Publishing activity and content approvals</div></div><div class="client-controls"><label for="clientSelect">Client</label><select id="clientSelect" aria-label="Select client"><option value="Datasignz CreativeMinds">Datasignz CreativeMinds</option><option value="De Sportwekker">De Sportwekker</option></select><button id="refresh" class="secondary">Refresh</button></div></div>
<div class="stats" id="stats"></div>
<div id="notice" role="status"></div>
<div class="dashboard-columns">
<section class="dashboard-panel"><div class="dashboard-panel-head"><span class="head-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 5H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9"/><path d="m8 12 3 3L22 4"/></svg></span><div><h2>Pending Approvals (<span id="pendingCount">0</span>)</h2><p>Review, edit and approve content for publishing</p></div></div><div class="dashboard-panel-body" id="queue"></div></section>
<section class="dashboard-panel"><div class="dashboard-panel-head"><span class="head-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span><div><h2>Recent Activity</h2><p>Latest approvals, publications and updates</p></div></div><div class="dashboard-panel-body activity-list" id="recent"></div></section>
</div>
</main>
</div>
<script>
const $=id=>document.getElementById(id);
const labels={pending_approval:"Pending Approval",publishing:"Publishing",scheduled:"Scheduled",published:"Published",failed:"Failed",rejected:"Rejected"};
async function api(path,options={}){const r=await fetch(path,{...options,credentials:"same-origin",headers:{"Content-Type":"application/json",...(options.headers||{})}});let d={};try{d=await r.json()}catch{}if(r.status===401){showLogin();throw new Error("Your session has expired. Please sign in again.")}if(!r.ok)throw new Error(d.error||"Request failed");return d}
function showLogin(){ $("login").classList.remove("hidden");$("app").classList.add("hidden");$("logout").classList.add("hidden");}
function showApp(isGuest=false){ $("login").classList.add("hidden");$("app").classList.remove("hidden");$("logout").classList.remove("hidden");$("guestNote").classList.toggle("hidden",!isGuest);window.dashboardGuestMode=isGuest;}
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function itemHtml(x,actions=false){
 const p=x.payload||{};
 const photos=Array.isArray(p.media_urls)?p.media_urls:[];
 const video=p.video_url||"";
 const media=video
  ? '<div class="media-preview"><video controls playsinline preload="metadata" src="'+esc(video)+'">Your browser does not support video playback.</video></div>'
  : (photos.length
    ? '<div class="media-preview '+(photos.length>1?'multi':'')+'">'+photos.map((u,i)=>'<a href="'+esc(u)+'" target="_blank" rel="noopener"><img src="'+esc(u)+'" alt="Post image '+(i+1)+'" loading="lazy"></a>').join("")+'</div>'
    : '<div class="media-empty">No media attached</div>');
 const original=p.original_caption;
 const captionEditor=actions
  ? '<label class="caption-label" for="caption-'+esc(x.id)+'">Caption (editable)</label><textarea class="caption-editor" id="caption-'+esc(x.id)+'" maxlength="10000">'+esc(p.caption||"")+'</textarea>'+
    (original!==undefined&&original!==p.caption?'<details class="original-caption"><summary>View original AI caption</summary><div>'+esc(original)+'</div></details>':"")+
    '<div class="actions"><button class="secondary" data-action="save-caption" data-id="'+esc(x.id)+'">▣ &nbsp;Save changes</button><button data-action="approve" data-id="'+esc(x.id)+'">✓ &nbsp;Approve &amp; Publish</button><button class="danger" data-action="reject" data-id="'+esc(x.id)+'">× &nbsp;Reject</button></div>'
  : '<div class="caption">'+esc(p.caption||"(No caption)")+'</div>';
 const platform=(p.platforms||[]).join(", ")||"—";
 const url=x.publish_response?.url||x.publish_response?.post_url||x.publish_response?.results?.instagram?.url||"";
 return '<article class="item approval-card"><div class="approval-media">'+media+'</div><div class="approval-content"><div class="item-top"><strong>'+esc(p.user||x.submitted_by||"Content item")+'</strong><span class="platform-tag">◎ &nbsp;'+esc(platform)+'</span><span class="submitted">Submitted: '+esc(x.submitted_at?new Date(x.submitted_at).toLocaleString():"—")+'</span></div>'+captionEditor+'<div class="meta">'+(x.review_note?'<span class="error">'+esc(x.review_note)+'</span>':"")+(url?'<a href="'+esc(url)+'" target="_blank" rel="noopener">View published post</a>':"")+'</div></div></article>';
}
function activityHtml(x){
 const p=x.payload||{};
 const status=x.status||"";
 const platform=(p.platforms||[]).map(v=>String(v).toLowerCase()).join(" ");
 const platformIcon=platform.includes("instagram")?'<span class="social-icon instagram">◎</span>':platform.includes("facebook")?'<span class="social-icon facebook">f</span>':'<span class="social-icon other">●</span>';
 const title=p.caption||p.user||x.request_id||"Content update";
 const date=x.updated_at||x.submitted_at;
 const url=x.publish_response?.url||x.publish_response?.post_url||x.publish_response?.results?.instagram?.url||"";
 return '<div class="activity-row"><span class="activity-status '+esc(status)+'">'+esc(labels[status]||status)+'</span>'+platformIcon+'<span class="activity-title" title="'+esc(title)+'">'+esc(title)+'</span><time>'+esc(date?new Date(date).toLocaleString():"—")+'</time>'+(url?'<a class="activity-link" href="'+esc(url)+'" target="_blank" rel="noopener" aria-label="Open post">↗</a>':"")+'</div>';
}
async function load(){
 $("notice").textContent="Refreshing dashboard…";
 try{
  const selectedClient=$("clientSelect").value;
  const d=await api("/api/dashboard/overview?client="+encodeURIComponent(selectedClient));
  const readOnly=Boolean(window.dashboardGuestMode);
  const totals=d.totals||{};
  const statIcons={
   pending_approval:'<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 11.5 21 3l-6.5 18-3.2-7.3L3 11.5Z"/><path d="m11.3 13.7 4.4-4.4"/></svg>',
   publishing:'<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5" stroke-dasharray="2 4"/><circle cx="12" cy="3.5" r="1.5" class="dot"/></svg>',
   scheduled:'<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="5" width="18" height="16" rx="2"/><path d="M7 2v6M17 2v6M3 10h18M8 14h3M8 17h6"/></svg>',
   published:'<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="m7.5 12.2 3 3 6-6.5"/></svg>',
   failed:'<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10.3 3.8 2.6 18a2 2 0 0 0 1.8 3h15.2a2 2 0 0 0 1.8-3L13.7 3.8a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4.5M12 17h.01"/></svg>',
   rejected:'<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="m9 9 6 6m0-6-6 6"/></svg>'
  };
  $("stats").innerHTML=Object.entries(labels).map(([k,v])=>{
   const count=k==="publishing"?(totals.publishing||0)+(totals.submitted||0):(totals[k]||0);
   return '<div class="stat '+k+'"><span class="stat-icon">'+statIcons[k]+'</span><div><div class="num">'+count+'</div><div class="label">'+v+'</div></div></div>';
  }).join("");
  const pending=(d.items||[]).filter(x=>x.status==="pending_approval");
  $("pendingCount").textContent=pending.length;
  $("queue").innerHTML=pending.length?pending.map(x=>itemHtml(x,!readOnly)).join(""):'<div class="panel muted">No items waiting for approval.</div>';
  $("recent").innerHTML=(d.items||[]).length?d.items.slice(0,8).map(x=>activityHtml(x)).join(""):'<div class="muted">No activity yet.</div>';
  $("notice").textContent="Last updated: "+new Date(d.generated_at).toLocaleString();
 }catch(e){$("notice").textContent=e.message}
}
$("guestButton").addEventListener("click",async()=>{ $("guestButton").disabled=true;$("loginError").textContent="";try{await api("/api/dashboard/guest",{method:"POST",body:"{}"});showApp(true);await load()}catch(err){$("loginError").textContent=err.message}finally{$("guestButton").disabled=false}});
$("loginForm").addEventListener("submit",async e=>{e.preventDefault();$("loginButton").disabled=true;$("loginError").textContent="";
 try{await api("/api/dashboard/login",{method:"POST",body:JSON.stringify({username:$("username").value,password:$("password").value})});$("password").value="";showApp();await load()}
 catch(err){$("loginError").textContent=err.message}finally{$("loginButton").disabled=false}});
$("logout").addEventListener("click",async()=>{try{await api("/api/dashboard/logout",{method:"POST",body:"{}"})}finally{window.dashboardGuestMode=false;showLogin()}});
$("refresh").addEventListener("click",load);
$("clientSelect").addEventListener("change",load);
$("queue").addEventListener("click",async e=>{const b=e.target.closest("button[data-action]");if(!b)return;const action=b.dataset.action;const id=b.dataset.id;
 if(action==="save-caption"){
  const field=$("caption-"+id);if(!field)return;
  b.disabled=true;$("notice").textContent="Saving caption…";
  try{await api("/api/approval/"+encodeURIComponent(id)+"/caption",{method:"POST",body:JSON.stringify({caption:field.value})});$("notice").textContent="Caption saved.";await load()}
  catch(err){$("notice").textContent=err.message;b.disabled=false}
  return;
 }
 if(action==="reject"){
  const card=b.closest(".item");
  if(!card)return;
  if(card.querySelector(".rejection-editor"))return;
  const editor=document.createElement("div");
  editor.className="rejection-editor";
  editor.innerHTML='<label for="rejection-'+esc(id)+'">Comments / changes required</label><textarea id="rejection-'+esc(id)+'" maxlength="2000" placeholder="Explain what the client needs to change before resubmitting…"></textarea><div class="actions"><button data-action="submit-rejection" data-id="'+esc(id)+'">Send feedback &amp; reject</button><button class="secondary" data-action="cancel-rejection" data-id="'+esc(id)+'">Cancel</button></div>';
  b.closest(".actions").insertAdjacentElement("afterend",editor);
  editor.querySelector("textarea").focus();
  return;
 }
 if(action==="cancel-rejection"){b.closest(".rejection-editor")?.remove();return}
 if(action==="submit-rejection"){
  const reason=$("rejection-"+id)?.value.trim()||"";
  if(!reason){$("notice").textContent="Please add comments describing the required changes.";return}
  b.disabled=true;$("notice").textContent="Sending feedback and rejecting…";
  try{await api("/api/approval/"+encodeURIComponent(id)+"/reject",{method:"POST",body:JSON.stringify({reviewed_by:"dashboard",reason})});await load()}
  catch(err){$("notice").textContent=err.message;b.disabled=false}
  return;
 }
 if(action==="approve"&&!confirm("Approve and publish this content now?"))return;
 b.disabled=true;$("notice").textContent="Publishing…";
 try{await api("/api/approval/"+encodeURIComponent(id)+"/approve",{method:"POST",body:JSON.stringify({reviewed_by:"dashboard"})});await load()}
 catch(err){$("notice").textContent=err.message;b.disabled=false}
});
(async()=>{try{const session=await api("/api/dashboard/me");showApp(Boolean(session.guest));await load()}catch{showLogin()}})();
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

app.post("/api/dashboard/guest", async (request, reply) => {
  const signingSecret = process.env.DASHBOARD_SESSION_SECRET;
  if (!signingSecret) {
    return reply.code(503).send({ success: false, error: "Dashboard guest access is not configured" });
  }
  const expiresAt = Math.floor(Date.now() / 1000) + dashboardSessionLifetimeSeconds;
  const signature = createHmac("sha256", signingSecret)
    .update(`neuralnext-guest:${expiresAt}`)
    .digest("hex");
  reply.header("Set-Cookie", `${guestCookieName}=${expiresAt}.${signature}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${dashboardSessionLifetimeSeconds}`);
  return { success: true, guest: true, expires_at: new Date(expiresAt * 1000).toISOString() };
});

app.get("/api/dashboard/me", async (request, reply) => {
  if (hasDashboardSession(request)) return { success: true, authenticated: true, guest: false };
  if (hasGuestSession(request)) return { success: true, authenticated: true, guest: true };
  return reply.code(401).send({ success: false, error: "Not authenticated" });
});

app.post("/api/dashboard/logout", async (request, reply) => {
  reply.header("Set-Cookie", [
    `${dashboardCookieName}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`,
    `${guestCookieName}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
  ]);
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

  const allowedClients = ["Datasignz CreativeMinds", "De Sportwekker"];
  const clientName = String(body.client_name || "Datasignz CreativeMinds").trim();
  if (!allowedClients.includes(clientName)) {
    return reply.code(400).send({ success: false, error: "client_name must be Datasignz CreativeMinds or De Sportwekker" });
  }

  const payload = {
    client_name: clientName,
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



// Edit a pending post caption before approval. Preserve the first submitted caption for audit.
app.post("/api/approval/:id/caption", async (request, reply) => {
  if (!requireReviewAccess(request, reply)) return;
  if (!requireDb(reply)) return;

  const caption = request.body?.caption;
  if (typeof caption !== "string" || caption.length > 10000) {
    return reply.code(400).send({
      success: false,
      error: "caption must be text no longer than 10,000 characters"
    });
  }

  try {
    const result = await pool.query(
      `UPDATE approval_items
       SET payload = jsonb_set(
         CASE
           WHEN payload ? 'original_caption' THEN payload
           ELSE payload || jsonb_build_object('original_caption', COALESCE(payload->>'caption', ''))
         END,
         '{caption}',
         to_jsonb($2::text),
         true
       ),
       updated_at = NOW()
       WHERE id = $1 AND status = 'pending_approval'
       RETURNING id, status, payload->>'caption' AS caption,
                 payload->>'original_caption' AS original_caption, updated_at`,
      [request.params.id, caption]
    );

    if (!result.rowCount) {
      return reply.code(409).send({
        success: false,
        error: "Item not found or no longer pending approval"
      });
    }

    return { success: true, item: result.rows[0] };
  } catch (error) {
    if (error.code === "22P02") {
      return reply.code(400).send({ success: false, error: "Invalid approval ID" });
    }
    request.log.error({ err: error }, "Caption update failed");
    return reply.code(500).send({ success: false, error: "Could not save caption" });
  }
});

// Dashboard overview: status counts and latest approval/publication records.
app.get("/api/dashboard/overview", async (request, reply) => {
  if (!requireDashboardReadAccess(request, reply)) return;
  if (!requireDb(reply)) return;

  try {
    const allowedClients = ["Datasignz CreativeMinds", "De Sportwekker"];
    const client = String(request.query?.client || "Datasignz CreativeMinds");
    if (!allowedClients.includes(client)) {
      return reply.code(400).send({ success: false, error: "Unknown client" });
    }

    const counts = await pool.query(
      `SELECT status, COUNT(*)::int AS count
       FROM approval_items
       WHERE COALESCE(payload->>'client_name', 'Datasignz CreativeMinds') = $1
       GROUP BY status`,
      [client]
    );

    const recent = await pool.query(
      `SELECT id, request_id, status, payload, submitted_by,
              reviewed_by, review_note, submitted_at, reviewed_at,
              updated_at, upload_post_job_id, upload_post_request_id,
              publish_response
       FROM approval_items
       WHERE COALESCE(payload->>'client_name', 'Datasignz CreativeMinds') = $1
       ORDER BY submitted_at DESC
       LIMIT 50`,
      [client]
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
      client,
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
