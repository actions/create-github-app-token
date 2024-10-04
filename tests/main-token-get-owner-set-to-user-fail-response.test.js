import { test } from "./main.js";

// Verify retries work when getting a token for a user or organization fails on the first attempt.
await test((mockPool) => {
  process.env.INPUT_OWNER = "smockle";
  delete process.env.INPUT_REPOSITORIES;

  // Mock installation ID and app slug request
  const mockInstallationId = "123456";
  const mockAppSlug = "github-actions";
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
    .reply(500, "GitHub API not available");
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
      { id: mockInstallationId, "app_slug": mockAppSlug },
      { headers: { "content-type": "application/json" } }
    );
});
