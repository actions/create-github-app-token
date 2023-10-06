// Verify `main` creates a token when the `owner` input is set (specifically, to a user) but the `repositories` input is not set.
// @ts-check
import { readFileSync } from "node:fs";
import * as url from "node:url";
import { MockAgent, setGlobalDispatcher } from "undici";

// Set required environment variables and inputs
process.env.GITHUB_REPOSITORY_OWNER = "actions";
process.env.GITHUB_REPOSITORY = "actions/create-github-app-token";
// inputs are set as environment variables with the prefix INPUT_
// https://docs.github.com/en/actions/creating-actions/metadata-syntax-for-github-actions#example-specifying-inputs
process.env.INPUT_OWNER = "smockle";
delete process.env.INPUT_REPOSITORIES;
process.env.INPUT_APP_ID = "123456";
process.env.INPUT_PRIVATE_KEY = readFileSync(
  url.fileURLToPath(new URL("./data/mock-private-key.pem", import.meta.url)),
  "utf8"
); // This key is invalidated. It’s from https://github.com/octokit/auth-app.js/issues/465#issuecomment-1564998327.

// Set up mocking
const mockAgent = new MockAgent();
mockAgent.disableNetConnect();
setGlobalDispatcher(mockAgent);
const mockPool = mockAgent.get("https://api.github.com");

// Calling `auth({ type: "app" })` to obtain a JWT doesn’t make network requests, so no need to intercept.

// Mock installation id requests
const mockInstallationId = "123456";
mockPool
  .intercept({
    path: `/orgs/${process.env.INPUT_OWNER}/installation`,
    method: "GET",
    headers: {
      accept: "application/vnd.github.v3+json",
      "user-agent": "actions/create-github-app-token",
      // Intentionally omitting the `authorization` header, since JWT creation is not idempotent.
    },
  })
  .reply(404);
mockPool
  .intercept({
    path: `/users/${process.env.INPUT_OWNER}/installation`,
    method: "GET",
    headers: {
      accept: "application/vnd.github.v3+json",
      "user-agent": "actions/create-github-app-token",
      // Intentionally omitting the `authorization` header, since JWT creation is not idempotent.
    },
  })
  .reply(
    200,
    { id: mockInstallationId },
    { headers: { "content-type": "application/json" } }
  );

// Mock installation access token request
const mockInstallationAccessToken = "ghs_16C7e42F292c6912E7710c838347Ae178B4a"; // This token is invalidated. It’s from https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app.
mockPool
  .intercept({
    path: `/app/installations/${mockInstallationId}/access_tokens`,
    method: "POST",
    headers: {
      accept: "application/vnd.github.v3+json",
      "user-agent": "actions/create-github-app-token",
      // Note: Intentionally omitting the `authorization` header, since JWT creation is not idempotent.
    },
  })
  .reply(201, { token: mockInstallationAccessToken });

// Run the main script
await import("../main.js");
