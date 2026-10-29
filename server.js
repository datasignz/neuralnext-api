import Fastify from "fastify";
import multipart from "@fastify/multipart";
import { randomUUID } from "node:crypto";

const app = Fastify({
  logger: true,
  bodyLimit: 500 * 1024 * 1024
});

await app.register(multipart, {
  limits: {
    fileSize: 500 * 1024 * 1024
  }
});

const uploadPostBaseUrl = () =>
  (process.env.UPLOAD_POST_API_URL || "https://api.upload-post.com").replace(/\/+$/, "");

app.get("/", async () => ({
  name: "NeuralNext Engage API",
  status: "online"
}));

app.get("/health", async () => ({
  status: "ok"
}));

// Proxy Upload-Post status without exposing the API key to clients.
app.get("/api/uploadposts/status", async (request, reply) => {
  const apiKey = process.env.UPLOAD_POST_API_KEY;
  if (!apiKey) {
    return reply.code(500).send({
      success: false,
      error: "UPLOAD_POST_API_KEY is not configured"
    });
  }

  const { request_id: requestId, job_id: jobId } = request.query || {};
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
      `${uploadPostBaseUrl()}/api/uploadposts/status?${params.toString()}`,
      {
        method: "GET",
        headers: { Authorization: `Apikey ${apiKey}` },
        signal: AbortSignal.timeout(30_000)
      }
    );

    const text = await response.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = { success: false, error: text };
    }

    return reply.code(response.status).send(data);
  } catch (error) {
    request.log.error({ err: error }, "Upload-Post status request failed");
    return reply.code(502).send({
      success: false,
      error: "Could not retrieve publishing status from Upload-Post"
    });
  }
});

app.post("/api/social/publish", async (request, reply) => {
  try {
    const apiKey = process.env.UPLOAD_POST_API_KEY;
    if (!apiKey) {
      return reply.code(500).send({
        success: false,
        error: "UPLOAD_POST_API_KEY is not configured"
      });
    }

    const form = new FormData();
    const mediaTypes = new Set();
    let fileCount = 0;
    let videoCount = 0;

    for await (const part of request.parts()) {
      if (part.type === "file") {
        const isVideo = part.mimetype?.startsWith("video/") ||
          /\.(mp4|mov|mpeg|mpg|webm|m4v)$/i.test(part.filename || "");
        const mediaType = isVideo ? "video" : "photo";
        mediaTypes.add(mediaType);

        if (isVideo) videoCount++;
        if (videoCount > 1) {
          return reply.code(400).send({
            success: false,
            error: "Only one video file can be published per request"
          });
        }

        const buffer = await part.toBuffer();
        form.append(
          isVideo ? "video" : "photos[]",
          new Blob([buffer], {
            type: part.mimetype || (isVideo ? "video/mp4" : "application/octet-stream")
          }),
          part.filename || (isVideo ? "video.mp4" : "photo")
        );
        fileCount++;
      } else {
        form.append(part.fieldname, part.value);
      }
    }

    if (fileCount === 0) {
      return reply.code(400).send({
        success: false,
        error: "No photo or video was provided"
      });
    }

    if (mediaTypes.size > 1) {
      return reply.code(400).send({
        success: false,
        error: "Send either photos or one video per request, not mixed media"
      });
    }

    const mediaType = mediaTypes.has("video") ? "video" : "photo";
    const endpoint = mediaType === "video" ? "/api/upload" : "/api/upload_photos";
    const requestId = String(request.headers["x-request-id"] || randomUUID());

    // Scheduled posts use Upload-Post's scheduler. Dates should be ISO-8601.
    // When callers provide a local date/time without a timezone field, interpret it
    // in Suriname time by default. Callers may override this with an IANA timezone.
    if (form.has("scheduled_date") && !form.has("timezone")) {
      form.set("timezone", "America/Paramaribo");
    }

    // Always send a stable request ID to Upload-Post for status tracking, for both
    // photos and videos. Callers should reuse X-Request-Id when retrying a request.
    form.set("request_id", requestId);

    // Upload-Post documents Idempotency-Key, X-Idempotency-Key, and X-Request-Id
    // as duplicate-prevention keys (24-hour window). Prefer an explicit idempotency
    // key; otherwise use the caller's stable X-Request-Id.
    if (mediaType === "video") {
      form.set("async_upload", "true");
    }

    const headers = {
      Authorization: `Apikey ${apiKey}`
    };

    const idempotencyKey =
      request.headers["idempotency-key"] ||
      request.headers["x-idempotency-key"] ||
      request.headers["x-request-id"];
    if (idempotencyKey) {
      headers["Idempotency-Key"] = String(idempotencyKey);
    }

    request.log.info({
      mediaType,
      endpoint,
      requestId,
      fileCount
    }, "Forwarding publish request to Upload-Post");

    const response = await fetch(`${uploadPostBaseUrl()}${endpoint}`, {
      method: "POST",
      headers,
      body: form,
      signal: AbortSignal.timeout(10 * 60 * 1000)
    });

    const text = await response.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = { success: false, error: text };
    }

    if (mediaType === "video" && data && typeof data === "object" && !data.request_id) {
      data.request_id = requestId;
    }

    return reply.code(response.status).send(data);
  } catch (error) {
    request.log.error({ err: error }, "Social publishing request failed");
    return reply.code(500).send({
      success: false,
      error: error.message || "Unexpected publishing error"
    });
  }
});

const port = Number(process.env.PORT || 3000);
const host = "0.0.0.0";

try {
  await app.listen({ port, host });
  app.log.info(`NeuralNext API running on port ${port}`);
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
