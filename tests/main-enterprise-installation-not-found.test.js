import { test } from "./main.js";


// Verify `main` handles when no enterprise installation is found.
await test((mockPool) => {
  delete process.env.INPUT_OWNER;
  delete process.env.INPUT_REPOSITORIES;  
  process.env.INPUT_ENTERPRISE = "test-enterprise";
  

  // Mock the /app/installations endpoint to return only non-enterprise installations
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
          id: "111111",
          app_slug: "github-actions",
          target_type: "Organization",
          account: { login: "some-org" }
        },
        {
          id: "222222",
          app_slug: "github-actions",
          target_type: "User",
          account: { login: "some-user" }
        }
      ],
      { headers: { "content-type": "application/json" } }
    );
});
