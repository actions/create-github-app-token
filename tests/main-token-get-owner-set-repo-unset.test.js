import { test, getLogOnceOnPath } from "./main.js";

// Verify `main` successfully obtains a token when the `owner` input is set, and the `repositories` input isn’t set.
await test((mockPool) => {
  process.env.INPUT_OWNER = process.env.GITHUB_REPOSITORY_OWNER;
  delete process.env.INPUT_REPOSITORIES;

  // Mock installation ID and app slug request
  const mockInstallationId = "123456";
  const mockAppSlug = "github-actions";
  mockPool
    .intercept({
      path: getLogOnceOnPath(`/users/${process.env.INPUT_OWNER}/installation`),
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
