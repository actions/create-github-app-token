import { test, getLogOnceOnPath } from "./main.js";

// Verify `main` successfully obtains a token when neither the `owner` nor `repositories` input is set.
await test((mockPool) => {
  delete process.env.INPUT_OWNER;
  delete process.env.INPUT_REPOSITORIES;

  // Mock installation ID and app slug request
  const mockInstallationId = "123456";
  const mockAppSlug = "github-actions";
  mockPool
    .intercept({
      path: getLogOnceOnPath(
        `/repos/${process.env.GITHUB_REPOSITORY}/installation`,
      ),
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
