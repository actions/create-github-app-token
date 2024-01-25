import { test } from "./main.js";

// Verify `main` successfully obtains a token when the `owner` input is set (to a user), but the `repositories` input isn’t set.
await test((mockPool) => {
  process.env.INPUT_OWNER = "smockle";
  delete process.env.INPUT_REPOSITORIES;

  // Mock installation id request
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
    .reply(500, "GitHub API not available");
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
    .reply(
      200,
      { id: mockInstallationId },
      { headers: { "content-type": "application/json" } }
    );
});
