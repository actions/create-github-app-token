// Verify `main` creates a token when the `owner` input is set (specifically, to a user) but the `repositories` input is not set.
// @ts-check
import { test } from "./main.js";

await test((mockPool) => {
  delete process.env.INPUT_REPOSITORIES;
  const mockInstallationId = "123456";

  // Mock installation id request
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
