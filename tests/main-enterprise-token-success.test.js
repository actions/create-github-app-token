import { test } from "./main.js";

// Verify `main` successfully generates enterprise token with basic functionality.
await test((mockPool) => {
  process.env.INPUT_ENTERPRISE = "test-enterprise";
  delete process.env.INPUT_OWNER;
  delete process.env.INPUT_REPOSITORIES;

  // Mock the /app/installations endpoint to return an enterprise installation
  const mockInstallationId = "123456";
  const mockAppSlug = "github-actions";
  mockPool
    .intercept({
      path: "/app/installations",
      method: "GET",
      headers: {
        accept: "application/vnd.github.v3+json",
        "user-agent": "actions/create-github-app-token",
        // Intentionally omitting the `authorization` header, since JWT creation is not idempotent.
      },
    })
    .reply(
      200,
      [
        {
          id: mockInstallationId,
          app_slug: mockAppSlug,
          target_type: "Enterprise",
          account: { login: "test-enterprise" }
        }
      ],
      { headers: { "content-type": "application/json" } }
    );
});
