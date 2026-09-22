import Fastify from "fastify";

const app = Fastify({
  logger: true
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

const port = process.env.PORT || 3000;
const host = "0.0.0.0";

try {
  await app.listen({ port, host });
  console.log(`NeuralNext API running on port ${port}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
