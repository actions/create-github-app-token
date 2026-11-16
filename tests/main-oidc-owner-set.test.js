import { OIDC_ENV, test } from "./main.js";

// Verify `main` authenticates with an OIDC token when the `owner` input is set, and that the
// OIDC audience is derived from `GITHUB_SERVER_URL`.
await test((mockPool) => {
  process.env.GITHUB_SERVER_URL = "https://github.example.com";
  process.env.INPUT_OWNER = process.env.GITHUB_REPOSITORY_OWNER;
  delete process.env.INPUT_REPOSITORIES;

  mockPool
    .intercept({
      path: `/users/${process.env.INPUT_OWNER}/installation?client_id=${OIDC_ENV["INPUT_CLIENT-ID"]}`,
      method: "GET",
      headers: {
        accept: "application/vnd.github.v3+json",
        "user-agent": "actions/create-github-app-token",
        authorization: "Bearer oidc-token",
      },
    })
    .reply(
      200,
      { id: "123456", app_slug: "github-actions" },
      { headers: { "content-type": "application/json" } },
    );
}, OIDC_ENV);
