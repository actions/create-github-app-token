import { test } from "./main.js";

// Verify `main` successfully generates enterprise token with specific permissions.
await test((mockPool) => {
  process.env["INPUT_ENTERPRISE-SLUG"] = "test-enterprise";
  delete process.env.INPUT_OWNER;
  delete process.env.INPUT_REPOSITORIES;
  process.env["INPUT_PERMISSION-ENTERPRISE-ORGANIZATIONS"] = "read";
  process.env["INPUT_PERMISSION-ENTERPRISE-PEOPLE"] = "write";

  // Mock the enterprise installation endpoint
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
    .reply(
      200,
      {
        id: mockInstallationId,
        app_slug: mockAppSlug,
      },
      { headers: { "content-type": "application/json" } }
    );
});
