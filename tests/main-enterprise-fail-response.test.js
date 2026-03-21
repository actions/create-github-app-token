import { test } from "./main.js";

// Verify enterprise installation lookup retries when the GitHub API returns a 500 error.
await test((mockPool) => {
  process.env.INPUT_ENTERPRISE = "test-enterprise";
  delete process.env.INPUT_OWNER;
  delete process.env.INPUT_REPOSITORIES;

  const mockInstallationId = "123456";
  const mockAppSlug = "github-actions";

  mockPool
    .intercept({
      path: "/enterprises/test-enterprise/installation",
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
      path: "/enterprises/test-enterprise/installation",
      method: "GET",
      headers: {
        accept: "application/vnd.github.v3+json",
        "user-agent": "actions/create-github-app-token",
        // Intentionally omitting the `authorization` header, since JWT creation is not idempotent.
      },
    })
    .reply(
      200,
      { id: mockInstallationId, app_slug: mockAppSlug },
      { headers: { "content-type": "application/json" } },
    );
});
