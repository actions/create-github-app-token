import { test } from "./main.js";

// Verify `main` handles when no enterprise installation is found.
await test((mockPool) => {
  delete process.env.INPUT_OWNER;
  delete process.env.INPUT_REPOSITORIES;
  process.env.INPUT_ENTERPRISE = "test-enterprise";

  // Mock the enterprise installation endpoint to return no matching installation
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
      404,
      { message: "Not Found" },
      { headers: { "content-type": "application/json" } }
    );
});
