import assert from "node:assert/strict";
import http from "node:http";

const ENV_KEYS = [
  "INPUT_GITHUB-API-URL",
  "HTTP_PROXY",
  "http_proxy",
  "HTTPS_PROXY",
  "https_proxy",
  "NO_PROXY",
  "no_proxy",
];

async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return server.address().port;
}

async function close(server) {
  await new Promise((resolve) => server.close(resolve));
}

function withEnv(overrides) {
  const previousEnv = Object.fromEntries(
    ENV_KEYS.map((key) => [key, process.env[key]]),
  );

  for (const key of ENV_KEYS) {
    delete process.env[key];
  }

  for (const [key, value] of Object.entries(overrides)) {
    process.env[key] = value;
  }

  return () => {
    for (const key of ENV_KEYS) {
      if (previousEnv[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = previousEnv[key];
      }
    }
  };
}

async function importRequest() {
  return (await import(`../lib/request.js?${Date.now()}-${Math.random()}`))
    .default;
}

async function testUsesProxyWhenConfigured() {
  const proxyEvents = [];
  const proxy = http.createServer((req, res) => {
    proxyEvents.push({
      type: "request",
      method: req.method,
      url: req.url,
      host: req.headers.host,
    });
    res.writeHead(502);
    res.end("proxy-bad");
  });

  proxy.on("connect", (req, socket) => {
    proxyEvents.push({
      type: "connect",
      method: req.method,
      url: req.url,
      host: req.headers.host,
    });
    socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
  });

  const proxyPort = await listen(proxy);
  const restoreEnv = withEnv({
    "INPUT_GITHUB-API-URL": "https://api.github.com",
    HTTP_PROXY: `http://127.0.0.1:${proxyPort}`,
  });

  try {
    const request = await importRequest();
    const proxyFetch = request.endpoint.DEFAULTS.request.fetch;

    assert.equal(typeof proxyFetch, "function");

    await assert.rejects(
      proxyFetch("http://example.test/through-proxy", {
        signal: AbortSignal.timeout(2_000),
      }),
      /fetch failed/,
    );

    assert.equal(
      proxyEvents.some((event) => event.type === "connect"),
      true,
      "proxy server saw a CONNECT request",
    );
  } finally {
    restoreEnv();
    await close(proxy);
  }
}

async function testWildcardNoProxyBypassesProxy() {
  const proxyEvents = [];
  const targetEvents = [];

  const proxy = http.createServer((req, res) => {
    proxyEvents.push({
      type: "request",
      method: req.method,
      url: req.url,
      host: req.headers.host,
    });
    res.writeHead(502);
    res.end("proxy-bad");
  });

  proxy.on("connect", (req, socket) => {
    proxyEvents.push({
      type: "connect",
      method: req.method,
      url: req.url,
      host: req.headers.host,
    });
    socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
  });

  const target = http.createServer((req, res) => {
    targetEvents.push({
      method: req.method,
      url: req.url,
      host: req.headers.host,
    });
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("target-ok");
  });

  const proxyPort = await listen(proxy);
  const targetPort = await listen(target);
  const restoreEnv = withEnv({
    "INPUT_GITHUB-API-URL": "https://api.github.com",
    HTTP_PROXY: `http://127.0.0.1:${proxyPort}`,
    NO_PROXY: "*",
  });

  try {
    const request = await importRequest();
    const response = await request.endpoint.DEFAULTS.request.fetch(
      `http://127.0.0.1:${targetPort}/bypass-proxy`,
      {},
    );

    assert.equal(response.status, 200);
    assert.equal(await response.text(), "target-ok");
    assert.equal(proxyEvents.length, 0, "proxy server was bypassed");
    assert.equal(targetEvents.length, 1, "target server saw one request");
  } finally {
    restoreEnv();
    await close(target);
    await close(proxy);
  }
}

await testUsesProxyWhenConfigured();
await testWildcardNoProxyBypassesProxy();
