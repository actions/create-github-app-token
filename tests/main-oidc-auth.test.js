import assert from "node:assert/strict";
import { mock } from "node:test";
import { request } from "@octokit/request";
import { createOidcAuth } from "../lib/create-oidc-auth.js";
import { main } from "../lib/main.js";
import { DEFAULT_ENV } from "./main.js";
import { createMockAgent } from "./mock-agent.js";

const { OidcClient } = await import(new URL("./oidc-utils.js", import.meta.resolve("@actions/core")));

process.env.ACTIONS_ID_TOKEN_REQUEST_URL = "https://oidc.example/token";
process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = "runner-token";
process.env.GITHUB_SERVER_URL = "https://github.com";

const mockAgent = createMockAgent();
const pool = mockAgent.get("https://api.github.com");
const clientId = "Iv1.0123456789abcdef";
const core = {
  async getIDToken(audience) {
    assert.equal(audience, "https://github.com/login/oauth");
    return "oidc-token";
  },
};

pool.intercept({
  path: `/repos/actions/repo/installation?client_id=${clientId}`,
  method: "GET",
  headers: { authorization: "Bearer oidc-token" },
}).reply(200, { id: 123, app_slug: "test-app" }, {
  headers: { "content-type": "application/json" },
});

pool.intercept({
  path: `/app/installations/123/access_tokens?client_id=${clientId}`,
  method: "POST",
  headers: { authorization: "Bearer oidc-token" },
  body: JSON.stringify({ repositories: ["repo"], permissions: { issues: "write" } }),
}).reply(201, { token: "installation-token", expires_at: "2026-11-10T12:00:00Z" }, {
  headers: { "content-type": "application/json" },
});

const auth = await createOidcAuth(clientId, core, request);
const installation = await request("GET /repos/{owner}/{repo}/installation", {
  owner: "actions",
  repo: "repo",
  request: { hook: auth.hook },
});
assert.equal(installation.data.id, 123);
assert.deepEqual(await auth({
  installationId: 123,
  repositoryNames: ["repo"],
  permissions: { issues: "write" },
}), { token: "installation-token", expiresAt: "2026-11-10T12:00:00Z" });

delete process.env.GITHUB_SERVER_URL;
process.env.GITHUB_REPOSITORY = "actions/repo";
const outputs = {};
const state = {};
const secrets = [];
const actionCore = {
  ...core,
  info() {},
  setSecret(token) { secrets.push(token); },
  setOutput(name, value) { outputs[name] = value; },
  saveState(name, value) { state[name] = value; },
};
const noKeyAuth = () => { throw new Error("Private-key auth must not be used"); };

for (const owner of ["", "actions"]) {
  pool.intercept({
    path: owner
      ? `/users/actions/installation?client_id=${clientId}`
      : `/repos/actions/repo/installation?client_id=${clientId}`,
    method: "GET",
    headers: { authorization: "Bearer oidc-token" },
  }).reply(200, { id: 123, app_slug: "test-app" }, {
    headers: { "content-type": "application/json" },
  });
  pool.intercept({
    path: `/app/installations/123/access_tokens?client_id=${clientId}`,
    method: "POST",
    headers: { authorization: "Bearer oidc-token" },
    ...(owner ? {} : { body: JSON.stringify({ repositories: ["repo"] }) }),
  }).reply(201, { token: "installation-token", expires_at: "2026-11-10T12:00:00Z" }, {
    headers: { "content-type": "application/json" },
  });
  await main(clientId, "", "", owner, [], undefined, actionCore, noKeyAuth, request, Boolean(owner));
}
assert.deepEqual(outputs, {
  token: "installation-token",
  "installation-id": 123,
  "app-slug": "test-app",
});
assert.deepEqual(state, { token: "installation-token", expiresAt: "2026-11-10T12:00:00Z" });
assert.deepEqual(secrets, ["installation-token", "installation-token"]);
await assert.rejects(
  main(clientId, "", "enterprise", "", [], undefined, actionCore, noKeyAuth, request, false),
  /requires 'private-key'/,
);
await assert.rejects(createOidcAuth(clientId, {
  ...core,
  async getIDToken() { throw new Error("OIDC provider unavailable"); },
}, request), /OIDC provider unavailable/);
delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
await assert.rejects(createOidcAuth(clientId, core, request), /id-token: write/);
delete process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
await assert.rejects(createOidcAuth(clientId, core, request), /id-token: write/);

Object.assign(process.env, DEFAULT_ENV, {
  "INPUT_PRIVATE-KEY": "",
  "INPUT_REPOSITORIES": "repo,another-repo",
  "INPUT_PERMISSION-ISSUES": "write",
  ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token",
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runner-token",
});
const oidcMock = mock.method(OidcClient, "getIDToken", core.getIDToken);
pool.intercept({
  path: `/repos/actions/repo/installation?client_id=${clientId}`,
  method: "GET",
  headers: { authorization: "Bearer oidc-token" },
}).reply(200, { id: 123, app_slug: "test-app" }, {
  headers: { "content-type": "application/json" },
});
pool.intercept({
  path: `/app/installations/123/access_tokens?client_id=${clientId}`,
  method: "POST",
  headers: { authorization: "Bearer oidc-token" },
  body: JSON.stringify({ repositories: ["repo", "another-repo"], permissions: { issues: "write" } }),
}).reply(201, { token: "installation-token", expires_at: "2026-11-10T12:00:00Z" }, {
  headers: { "content-type": "application/json" },
});
await (await import("../main.js")).default;
assert.equal(process.exitCode ?? 0, 0);
assert.equal(oidcMock.mock.callCount(), 1);
oidcMock.mock.restore();
mockAgent.assertNoPendingInterceptors();
await mockAgent.close();