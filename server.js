import Fastify from "fastify";
import multipart from "@fastify/multipart";

const app = Fastify({
  logger: true,
  bodyLimit: 500 * 1024 * 1024
});

await app.register(multipart, {
  limits: {
    fileSize: 500 * 1024 * 1024
  }
});

app.get("/", async () => {
  return {
    name: "NeuralNext Engage API",
    status: "online"
  };
});

app.get("/health", async () => {
  return {
    status: "ok"
  };
});

app.post("/api/social/publish", async (request, reply) => {
  try {
    const apiKey = process.env.UPLOAD_POST_API_KEY;
    const apiUrl =
      process.env.UPLOAD_POST_API_URL ||
      "https://api.upload-post.com";

    if (!apiKey) {
      return reply.code(500).send({
        success: false,
        error: "UPLOAD_POST_API_KEY is not configured"
      });
    }

    const form = new FormData();

    const parts = request.parts();

    let mediaType = null;
    let fileCount = 0;

    for await (const part of parts) {

      if (part.type === "file") {

        const buffer = await part.toBuffer();

        mediaType = part.mimetype?.startsWith("video/")
          ? "video"
          : "photo";

        const fieldName =
          mediaType === "video"
            ? "video"
            : "photos[]";

        form.append(
          fieldName,
          new Blob([buffer], {
            type: part.mimetype
          }),
          part.filename
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

    let endpoint;

    if (mediaType === "video") {
      endpoint = "/api/upload";
    } else {
      endpoint = "/api/upload_photos";
    }

    request.log.info({
      mediaType,
      endpoint
    }, "Publishing media");

    const response = await fetch(
      `${apiUrl}${endpoint}`,
      {
        method: "POST",
        headers: {
          Authorization: `Apikey ${apiKey}`
        },
        body: form
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

    return reply.code(response.status).send(data);

  } catch (error) {

    request.log.error(error);

    return reply.code(500).send({
      success: false,
      error: error.message
    });

  }
});

const port = Number(process.env.PORT || 3000);
const host = "0.0.0.0";

try {

  await app.listen({
    port,
    host
  });

  console.log(
    `NeuralNext API running on port ${port}`
  );

} catch (error) {

  app.log.error(error);
  process.exit(1);

}
