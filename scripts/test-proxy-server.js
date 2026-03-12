import http from "node:http";
import net from "node:net";
import { mkdir, appendFile } from "node:fs/promises";
import { dirname } from "node:path";

const logPath = process.argv[2];
const port = Number(process.argv[3] ?? 3128);

if (!logPath) {
  throw new Error("Usage: node scripts/test-proxy-server.js <log-path> [port]");
}

if (!Number.isInteger(port) || port <= 0) {
  throw new Error(`Invalid port: ${process.argv[3]}`);
}

await mkdir(dirname(logPath), { recursive: true });

function logEvent(event) {
  return appendFile(
    logPath,
    `${JSON.stringify({ ...event, timestamp: new Date().toISOString() })}\n`,
  ).catch((error) => {
    console.error("Failed to write proxy log", error);
  });
}

const server = http.createServer((req, res) => {
  void logEvent({
    event: "request",
    method: req.method,
    url: req.url,
    host: req.headers.host,
  });

  res.writeHead(501, { "content-type": "text/plain" });
  res.end("This test proxy only supports CONNECT requests.\n");
});

server.on("connect", (req, clientSocket, head) => {
  const { hostname, port: targetPortValue } = new URL(`http://${req.url}`);
  const targetPort = Number(targetPortValue || 80);

  void logEvent({
    event: "connect",
    target: req.url,
    host: req.headers.host,
  });

  const targetSocket = net.connect(targetPort, hostname, () => {
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");

    if (head.length > 0) {
      targetSocket.write(head);
    }

    clientSocket.pipe(targetSocket);
    targetSocket.pipe(clientSocket);
  });

  targetSocket.on("error", (error) => {
    void logEvent({
      event: "target-error",
      target: req.url,
      message: error.message,
    });

    clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
  });

  clientSocket.on("error", (error) => {
    void logEvent({
      event: "client-error",
      target: req.url,
      message: error.message,
    });

    targetSocket.destroy(error);
  });
});

server.on("clientError", (error, socket) => {
  void logEvent({
    event: "proxy-error",
    message: error.message,
  });

  socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
});

const shutdown = () => {
  server.close(() => {
    process.exit(0);
  });
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
console.log(`Proxy server listening on http://127.0.0.1:${port}`);
