import { spawn } from "node:child_process";
import { closeSync, openSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { mkdir, appendFile, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

function getProxyPidPath(logPath) {
  return `${logPath}.pid`;
}

function getProxyServerLogPath(logPath) {
  return `${logPath}.server.log`;
}

function isFileNotFoundError(error) {
  return error && typeof error === "object" && error.code === "ENOENT";
}

function isProcessMissingError(error) {
  return error && typeof error === "object" && error.code === "ESRCH";
}

function parsePort(value, usage) {
  const port = Number(value ?? 3128);

  if (!Number.isInteger(port) || port <= 0) {
    throw new Error(`${usage}\nInvalid port: ${value}`);
  }

  return port;
}

async function readEvents(logPath) {
  try {
    return (await readFile(logPath, "utf8"))
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch (error) {
    if (isFileNotFoundError(error)) {
      return [];
    }

    throw error;
  }
}

function isProcessRunning(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (isProcessMissingError(error)) {
      return false;
    }

    throw error;
  }
}

async function waitForProxyServer(logPath, pid, serverLogPath) {
  for (let attempt = 0; attempt < 30; attempt++) {
    const events = await readEvents(logPath);

    if (events.some((event) => event.event === "listening")) {
      return;
    }

    if (!isProcessRunning(pid)) {
      throw new Error(
        `Proxy server exited before it was ready. See ${serverLogPath}`,
      );
    }

    await delay(1000);
  }

  throw new Error(
    `Timed out waiting for proxy server readiness. See ${serverLogPath}`,
  );
}

async function printIfExists(path) {
  try {
    process.stdout.write(await readFile(path, "utf8"));
  } catch (error) {
    if (!isFileNotFoundError(error)) {
      throw error;
    }
  }
}

function reportLogWriteFailure(error) {
  console.error("Failed to write proxy log", error);
}

const command = process.argv[2];

if (command === "start") {
  const logPath = process.argv[3];
  const usage = "Usage: node scripts/test-proxy-server.js start <log-path> [port]";
  const port = parsePort(process.argv[4], usage);

  if (!logPath) {
    throw new Error(usage);
  }

  const pidPath = getProxyPidPath(logPath);
  const serverLogPath = getProxyServerLogPath(logPath);

  await mkdir(dirname(logPath), { recursive: true });
  await writeFile(logPath, "");
  await writeFile(serverLogPath, "");

  const serverLogFd = openSync(serverLogPath, "a");
  const child = spawn(
    process.execPath,
    [process.argv[1], "serve", logPath, String(port)],
    {
      detached: true,
      stdio: ["ignore", serverLogFd, serverLogFd],
    },
  );
  closeSync(serverLogFd);

  if (child.pid === undefined) {
    throw new Error("Failed to start proxy server");
  }

  child.unref();
  await writeFile(pidPath, `${child.pid}\n`);

  try {
    await waitForProxyServer(logPath, child.pid, serverLogPath);
  } catch (error) {
    if (isProcessRunning(child.pid)) {
      process.kill(child.pid, "SIGTERM");
    }

    throw error;
  }

  process.exit(0);
}

if (command === "assert") {
  const logPath = process.argv[3];
  const expectedTarget = process.argv[4];

  if (!logPath || !expectedTarget) {
    throw new Error(
      "Usage: node scripts/test-proxy-server.js assert <log-path> <expected-target>",
    );
  }

  const events = await readEvents(logPath);

  if (
    !events.some(
      (event) =>
        event.event === "connect" && event.target === expectedTarget,
    )
  ) {
    console.error(`Expected a CONNECT tunnel to ${expectedTarget}`);
    console.error(events);
    process.exit(1);
  }

  process.exit(0);
}

if (command === "logs") {
  const logPath = process.argv[3];

  if (!logPath) {
    throw new Error("Usage: node scripts/test-proxy-server.js logs <log-path>");
  }

  const serverLogPath = getProxyServerLogPath(logPath);

  await printIfExists(serverLogPath);
  await printIfExists(logPath);
  process.exit(0);
}

if (command === "stop") {
  const logPath = process.argv[3];

  if (!logPath) {
    throw new Error("Usage: node scripts/test-proxy-server.js stop <log-path>");
  }

  const pidPath = getProxyPidPath(logPath);
  let pidText;

  try {
    pidText = (await readFile(pidPath, "utf8")).trim();
  } catch (error) {
    if (isFileNotFoundError(error)) {
      process.exit(0);
    }

    throw error;
  }

  const pid = Number(pidText);

  if (!Number.isInteger(pid) || pid <= 0) {
    throw new Error(`Invalid proxy process ID in ${pidPath}: ${pidText}`);
  }

  if (!isProcessRunning(pid)) {
    process.exit(0);
  }

  process.kill(pid, "SIGTERM");

  for (let attempt = 0; attempt < 50; attempt++) {
    if (!isProcessRunning(pid)) {
      process.exit(0);
    }

    await delay(100);
  }

  throw new Error(`Timed out waiting for proxy server process ${pid} to exit`);
}

const usesServeSubcommand = command === "serve";
const logPath = process.argv[usesServeSubcommand ? 3 : 2];
const usage = usesServeSubcommand
  ? "Usage: node scripts/test-proxy-server.js serve <log-path> [port]"
  : "Usage: node scripts/test-proxy-server.js <log-path> [port]";
const port = parsePort(process.argv[usesServeSubcommand ? 4 : 3], usage);

if (!logPath) {
  throw new Error(usage);
}

await mkdir(dirname(logPath), { recursive: true });

async function logEvent(event) {
  await appendFile(
    logPath,
    `${JSON.stringify({ ...event, timestamp: new Date().toISOString() })}\n`,
  );
}

const server = http.createServer((req, res) => {
  void logEvent({
    event: "request",
    method: req.method,
    url: req.url,
    host: req.headers.host,
  }).catch(reportLogWriteFailure);

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
  }).catch(reportLogWriteFailure);

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
    }).catch(reportLogWriteFailure);

    clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
  });

  clientSocket.on("error", (error) => {
    void logEvent({
      event: "client-error",
      target: req.url,
      message: error.message,
    }).catch(reportLogWriteFailure);

    targetSocket.destroy(error);
  });
});

server.on("clientError", (error, socket) => {
  void logEvent({
    event: "proxy-error",
    message: error.message,
  }).catch(reportLogWriteFailure);

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
await logEvent({
  event: "listening",
  address: `http://127.0.0.1:${port}`,
});
console.log(`Proxy server listening on http://127.0.0.1:${port}`);
