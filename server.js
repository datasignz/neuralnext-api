import Fastify from "fastify";
import { randomUUID, timingSafeEqual } from "node:crypto";
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

function requireKey(request, reply, envName) {
  const expected = process.env[envName];
  const auth = request.headers.authorization || "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const supplied = request.headers["x-api-key"] || bearer;
  if (!expected) {
    reply.code(503).send({ success: false, error: `${envName} is not configured` });
    return false;
  }
  if (!secretMatches(supplied, expected)) {
    reply.code(401).send({ success: false, error: "Unauthorized" });
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

  if (statuses.includes("failed")) {
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
    reply.code(503).send({ success: false, error: "DATABASE_URL is not configured" });
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
  await pool.query("CREATE INDEX IF NOT EXISTS approval_items_status_submitted_idx ON approval_items (status, submitted_at DESC)");
}

app.get("/", async () => ({ name: "NeuralNext Engage API", status: "online" }));
app.get("/health", async () => ({ status: "ok" }));
app.get("/api/test/status-mapping", async (request, reply) => {
  if (!requireKey(request, reply, "APPROVAL_REVIEW_KEY")) return;

  const tests = [
    {
      name: "Completed",
      input: { success: true, status: "completed", job_id: "test-123" },
      expected: "published"
    },
    {
      name: "Scheduled",
      input: { success: true, status: "scheduled", job_id: "test-456" },
      expected: "scheduled"
    },
    {
      name: "Failed",
      input: { success: false, status: "failed" },
      expected: "failed"
    },
    {
      name: "Processing",
      input: { success: true, status: "processing", job_id: "test-789" },
      expected: "submitted"
    }
  ];

  const results = tests.map(test => {
    const actual = mapUploadPostStatus(test.input, true, false);

    return {
      name: test.name,
      expected: test.expected,
      actual,
      passed: actual === test.expected
    };
  });

  return {
    success: results.every(result => result.passed),
    results
  };
});

app.get("/api/uploadposts/status", async (request, reply) => {
  const apiKey = process.env.UPLOAD_POST_API_KEY;
  if (!apiKey) return reply.code(500).send({ success: false, error: "UPLOAD_POST_API_KEY is not configured" });
  const { request_id: requestId, job_id: jobId } = request.query || {};
  if (!requestId && !jobId) return reply.code(400).send({ success: false, error: "Provide request_id or job_id" });
  const params = new URLSearchParams();
  if (requestId) params.set("request_id", String(requestId));
  if (jobId) params.set("job_id", String(jobId));
  try {
    const response = await fetch(`${uploadPostBaseUrl()}/api/uploadposts/status?${params}`, {
      headers: { Authorization: `Apikey ${apiKey}` },
      signal: AbortSignal.timeout(30_000)
    });
    const text = await response.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { success: false, error: text }; }
    return reply.code(response.status).send(data);
  } catch (error) {
    request.log.error({ err: error }, "Upload-Post status request failed");
    return reply.code(502).send({ success: false, error: "Could not retrieve publishing status from Upload-Post" });
  }
});

// Submit metadata and public HTTPS media URLs for human review. This route never publishes.
app.post("/api/approval/submit", async (request, reply) => {
  if (!requireKey(request, reply, "APPROVAL_SUBMIT_KEY")) return;
  if (!requireDb(reply)) return;
  const body = request.body || {};
const platforms = Array.isArray(body.platforms) ? body.platforms : [];

const mediaUrls = Array.isArray(body.media_urls)
  ? body.media_urls.map((url) => {
      const value = String(url).trim();
      const markdownMatch = value.match(/^\[(https?:\/\/[^\]]+)\]\((https?:\/\/[^)]+)\)$/);
      return markdownMatch ? markdownMatch[2] : value;
    })
  : [];

request.log.info({
  receivedMediaUrls: body.media_urls,
  cleanedMediaUrls: mediaUrls
}, "Approval media URL normalization");
  const videoUrl = body.video_url;
  if (typeof body.user !== "string" || !body.user.trim()) {
    return reply.code(400).send({ success: false, error: "user is required" });
  }
  if (!platforms.length || platforms.some(p => typeof p !== "string" || !p.trim())) {
    return reply.code(400).send({ success: false, error: "platforms must be a non-empty array of platform names" });
  }
  if ((mediaUrls.length === 0) === !videoUrl) {
    return reply.code(400).send({ success: false, error: "Provide either media_urls (photo URLs) or video_url, but not both" });
  }
  if (mediaUrls.length > 20) return reply.code(400).send({ success: false, error: "A maximum of 20 photo URLs is supported" });
  const urls = videoUrl ? [videoUrl] : mediaUrls;
  if (urls.some(value => {
    try { const u = new URL(value); return u.protocol !== "https:"; } catch { return true; }
  })) {
    return reply.code(400).send({ success: false, error: "Media must use valid public HTTPS URLs" });
  }
  if (body.scheduled_date && Number.isNaN(Date.parse(body.scheduled_date))) {
    return reply.code(400).send({ success: false, error: "scheduled_date must be a valid ISO-8601 date/time" });
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
    extra_fields: body.extra_fields && typeof body.extra_fields === "object" && !Array.isArray(body.extra_fields) ? body.extra_fields : {}
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
  [id, requestId, JSON.stringify(payload), String(body.submitted_by || "agent").slice(0, 200)]
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
      return reply.code(200).send({ success: true, duplicate: true, item: existing.rows[0] });
    }
    return reply.code(201).send({ success: true, item: result.rows[0] });
  } catch (error) {
    request.log.error({ err: error }, "Approval submission failed");
    return reply.code(500).send({ success: false, error: "Could not save approval request" });
  }
});

app.get("/api/approval/pending", async (request, reply) => {
  if (!requireKey(request, reply, "APPROVAL_REVIEW_KEY")) return;
  if (!requireDb(reply)) return;
  try {
    const limit = Math.min(Math.max(Number(request.query?.limit) || 50, 1), 100);
    const result = await pool.query(
      "SELECT id, request_id, status, payload, submitted_by, submitted_at FROM approval_items WHERE status='pending_approval' ORDER BY submitted_at ASC LIMIT $1",
      [limit]
    );
request.log.info({
  pendingRecords: result.rows.map(row => ({
    id: row.id,
    requestId: row.request_id,
    mediaUrls: row.payload?.media_urls
  }))
}, "Pending endpoint database read-back");
    return { success: true, items: result.rows };
  } catch (error) {
    request.log.error({ err: error }, "Pending approval list failed");
    return reply.code(500).send({ success: false, error: "Could not list pending approvals" });
  }
});

app.get("/api/approval/:id/status", async (request, reply) => {
  if (!requireKey(request, reply, "APPROVAL_REVIEW_KEY")) return;
  if (!requireDb(reply)) return;
  try {
    const result = await pool.query(
      "SELECT id, request_id, status, reviewed_by, review_note, submitted_at, reviewed_at, updated_at, upload_post_job_id, upload_post_request_id, publish_response FROM approval_items WHERE id=$1",
      [request.params.id]
    );
    if (!result.rowCount) return reply.code(404).send({ success: false, error: "Approval item not found" });
    return { success: true, item: result.rows[0] };
  } catch (error) {
    if (error.code === "22P02") return reply.code(400).send({ success: false, error: "Invalid approval ID" });
    request.log.error({ err: error }, "Approval status lookup failed");
    return reply.code(500).send({ success: false, error: "Could not retrieve approval status" });
  }
});

app.post("/api/approval/:id/reject", async (request, reply) => {
  if (!requireKey(request, reply, "APPROVAL_REVIEW_KEY")) return;
  if (!requireDb(reply)) return;
  const note = String(request.body?.reason || "").slice(0, 2000);
  const reviewer = String(request.body?.reviewed_by || "reviewer").slice(0, 200);
  try {
    const result = await pool.query(
      `UPDATE approval_items SET status='rejected', reviewed_by=$2, review_note=$3,
       reviewed_at=NOW(), updated_at=NOW()
       WHERE id=$1 AND status='pending_approval'
       RETURNING id, request_id, status, reviewed_by, review_note, reviewed_at`,
      [request.params.id, reviewer, note]
    );
    if (!result.rowCount) return reply.code(409).send({ success: false, error: "Item not found or no longer pending approval" });
    return { success: true, item: result.rows[0] };
  } catch (error) {
    if (error.code === "22P02") return reply.code(400).send({ success: false, error: "Invalid approval ID" });
    request.log.error({ err: error }, "Approval rejection failed");
    return reply.code(500).send({ success: false, error: "Could not reject approval item" });
  }
});

app.post("/api/approval/:id/approve", async (request, reply) => {
  if (!requireKey(request, reply, "APPROVAL_REVIEW_KEY")) return;
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
      return reply.code(404).send({ success: false, error: "Approval item not found" });
    }
    item = selected.rows[0];
    if (item.status !== "pending_approval") {
      await client.query("ROLLBACK");
      return reply.code(409).send({ success: false, error: "Item is not pending approval", status: item.status });
    }
    await client.query(
      "UPDATE approval_items SET status='publishing', reviewed_by=$2, reviewed_at=NOW(), updated_at=NOW() WHERE id=$1",
      [item.id, String(request.body?.reviewed_by || "reviewer").slice(0, 200)]
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    if (error.code === "22P02") return reply.code(400).send({ success: false, error: "Invalid approval ID" });
    request.log.error({ err: error }, "Could not lock approval item");
    return reply.code(500).send({ success: false, error: "Could not begin approval" });
  } finally {
    client.release();
  }

  const apiKey = process.env.UPLOAD_POST_API_KEY;
  if (!apiKey) {
    await pool.query("UPDATE approval_items SET status='failed', review_note='UPLOAD_POST_API_KEY is not configured', updated_at=NOW() WHERE id=$1", [item.id]);
    return reply.code(503).send({ success: false, error: "UPLOAD_POST_API_KEY is not configured" });
  }

  const payload = item.payload;
  const isVideo = Boolean(payload.video_url);
  const form = new FormData();
  form.set("user", payload.user);
  for (const platform of payload.platforms) form.append("platform[]", platform);
  if (payload.caption) form.set("title", payload.caption);
  if (isVideo) form.set("video", payload.video_url);
  else for (const url of payload.media_urls) form.append("photos[]", url);
  if (payload.scheduled_date) {
    form.set("scheduled_date", payload.scheduled_date);
    form.set("timezone", payload.timezone || "America/Paramaribo");
  }
  form.set("request_id", `approval-${item.id}`);
  form.set("external_id", item.id);
  if (isVideo) form.set("async_upload", "true");
  for (const [key, value] of Object.entries(payload.extra_fields || {})) {
    if (["user", "platform[]", "photos[]", "video", "request_id", "scheduled_date", "timezone", "external_id"].includes(key)) continue;
    if (Array.isArray(value)) for (const v of value) form.append(key, String(v));
    else if (value !== null && value !== undefined) form.set(key, String(value));
  }

  try {
    const endpoint = isVideo ? "/api/upload" : "/api/upload_photos";
    const upstream = await fetch(`${uploadPostBaseUrl()}${endpoint}`, {
      method: "POST",
      headers: { Authorization: `Apikey ${apiKey}`, "Idempotency-Key": `approval-${item.id}` },
      body: form,
      signal: AbortSignal.timeout(10 * 60 * 1000)
    });
    const raw = await upstream.text();
    let data;
    try { data = JSON.parse(raw); } catch { data = { success: false, error: raw }; }
    const success = upstream.ok && data?.success !== false;

const nextStatus = mapUploadPostStatus(
  data,
  upstream.ok,
  isVideo
);
    await pool.query(
      `UPDATE approval_items SET status=$2, upload_post_job_id=$3, upload_post_request_id=$4,
       publish_response=$5::jsonb, review_note=$6, updated_at=NOW() WHERE id=$1`,
      [item.id, nextStatus, data.job_id || null, data.request_id || `approval-${item.id}`, JSON.stringify(data), success ? null : String(data.error || data.message || "Upload-Post request failed").slice(0, 2000)]
    );
    return reply.code(success ? 200 : (upstream.status >= 400 ? upstream.status : 502)).send({
      success, approval_id: item.id, status: nextStatus, upload_post: data
    });
  } catch (error) {
    request.log.error({ err: error, approvalId: item.id }, "Approved publishing request failed");
    await pool.query(
      "UPDATE approval_items SET status='failed', review_note=$2, updated_at=NOW() WHERE id=$1",
      [item.id, String(error.message || "Publishing request failed").slice(0, 2000)]
    );
    return reply.code(502).send({ success: false, approval_id: item.id, status: "failed", error: "Publishing request failed; check status before retrying" });
  }
});

// Direct publishing is disabled: all new content must pass through human approval.
app.post("/api/social/publish", async (request, reply) => {
  return reply.code(403).send({
    success: false,
    error: "Direct publishing is disabled. Submit content to /api/approval/submit and publish only after human approval."
  });
});

const port = Number(process.env.PORT || 3000);
try {
  await initializeDatabase();
  await app.listen({ port, host: "0.0.0.0" });
  app.log.info(`NeuralNext API running on port ${port}`);
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
