// Verify `main` creates a token when the `owner` input is set (specifically, to a user) but the `repositories` input is not set.
// @ts-check
import { test } from "./main.js";

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
});
