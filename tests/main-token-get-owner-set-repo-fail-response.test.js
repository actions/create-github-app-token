import { test } from "./main.js";

// Verify `main` retry when  the GitHub API returns a 500 error.
await test((mockPool) => {
  process.env.INPUT_OWNER = 'actions'
  process.env.INPUT_REPOSITORIES = 'failed-repo';
  const owner = process.env.INPUT_OWNER
  const repo = process.env.INPUT_REPOSITORIES
  const mockInstallationId = "123456";

  mockPool
    .intercept({
      path: `/repos/${owner}/${repo}/installation`,
      method: "GET",
      headers: {
        accept: "application/vnd.github.v3+json",
        "user-agent": "actions/create-github-app-token",
        // Intentionally omitting the `authorization` header, since JWT creation is not idempotent.
      },
    })
    .reply(500, 'GitHub API not available')
    
    mockPool
    .intercept({
      path: `/repos/${owner}/${repo}/installation`,
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
