import { test } from "./main.js";

// Verify `main` retry when  the GitHub API returns a 500 error.
await test((mockPool) => {
  process.env.INPUT_OWNER = process.env.GITHUB_REPOSITORY_OWNER;
  process.env.INPUT_REPOSITORIES = process.env.GITHUB_REPOSITORY;

  // Mock installation id request
  const mockInstallationId = "123456";
  mockPool
    .intercept({
      path: `/repos/${process.env.INPUT_OWNER}/${process.env.INPUT_REPOSITORIES}/installation`,
      method: "GET",
      headers: {
        accept: "application/vnd.github.v3+json",
        "user-agent": "actions/create-github-app-token",
        // Intentionally omitting the `authorization` header, since JWT creation is not idempotent.
      },
    })
    .reply(500)
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
