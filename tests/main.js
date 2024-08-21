// Base for all `main` tests.
// @ts-check
import { MockAgent, setGlobalDispatcher } from "undici";

export const DEFAULT_ENV = {
  GITHUB_REPOSITORY_OWNER: "lepadatu-org",
  GITHUB_REPOSITORY: "lepadatu-org/create-github-app-token-aws",
  // inputs are set as environment variables with the prefix INPUT_
  // https://docs.github.com/actions/creating-actions/metadata-syntax-for-github-actions#example-specifying-inputs
  "INPUT_GITHUB-API-URL": "https://api.github.com",
  "INPUT_APP-ID": "123456",
  // This key is invalidated. It’s from https://github.com/octokit/auth-app.js/issues/465#issuecomment-1564998327.
  "INPUT_KMS_KEY_ID": `1234abcd-12ab-34cd-56ef-1234567890ab`,
};

export async function test(cb = (_mockPool) => {}, env = DEFAULT_ENV) {
  for (const [key, value] of Object.entries(env)) {
    process.env[key] = value;
  }

  // Set up mocking
  const baseUrl = new URL(env["INPUT_GITHUB-API-URL"]);
  const basePath = baseUrl.pathname === '/' ? '' : baseUrl.pathname;
  const mockAgent = new MockAgent();
  mockAgent.disableNetConnect();
  setGlobalDispatcher(mockAgent);
  const mockPool = mockAgent.get(baseUrl.origin);

  // Calling `auth({ type: "app" })` to obtain a JWT doesn’t make network requests, so no need to intercept.

  // Mock installation ID and app slug request
  const mockInstallationId = "123456";
  const mockAppSlug = "github-actions";
  const owner = env.INPUT_OWNER ?? env.GITHUB_REPOSITORY_OWNER;
  const repo = encodeURIComponent(
    (env.INPUT_REPOSITORIES ?? env.GITHUB_REPOSITORY).split(",")[0]
  );
  mockPool
    .intercept({
      path: `${basePath}/repos/${owner}/${repo}/installation`,
      method: "GET",
      headers: {
        accept: "application/vnd.github.v3+json",
        "user-agent": "actions/create-github-app-token",
        // Intentionally omitting the `authorization` header, since JWT creation is not idempotent.
      },
    })
    .reply(
      200,
      { id: mockInstallationId, "app_slug": mockAppSlug },
      { headers: { "content-type": "application/json" } }
    );

  // Mock installation access token request
  const mockInstallationAccessToken =
    "ghs_16C7e42F292c6912E7710c838347Ae178B4a"; // This token is invalidated. It’s from https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app.
  const mockExpiresAt = "2016-07-11T22:14:10Z";
  mockPool
    .intercept({
      path: `${basePath}/app/installations/${mockInstallationId}/access_tokens`,
      method: "POST",
      headers: {
        accept: "application/vnd.github.v3+json",
        "user-agent": "actions/create-github-app-token",
        // Note: Intentionally omitting the `authorization` header, since JWT creation is not idempotent.
      },
    })
    .reply(
      201,
      { token: mockInstallationAccessToken, expires_at: mockExpiresAt },
      { headers: { "content-type": "application/json" } }
    );

  // Run the callback
  cb(mockPool);

  // Run the main script
  await import("../main.js");
}
