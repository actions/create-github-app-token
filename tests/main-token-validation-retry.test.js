import { test } from "./main.js";

// Verify `main` retries token validation when it fails on the first attempt.
await test((mockPool) => {
  delete process.env.INPUT_OWNER;
  delete process.env.INPUT_REPOSITORIES;

  const mockInstallationAccessToken =
    "ghs_16C7e42F292c6912E7710c838347Ae178B4a";

  // Prepend a failure response for the first validation attempt.
  // The base helper will register the success response after this callback.
  mockPool
    .intercept({
      path: `/installation/repositories?per_page=1`,
      method: "GET",
      headers: {
        accept: "application/vnd.github.v3+json",
        "user-agent": "actions/create-github-app-token",
        authorization: `token ${mockInstallationAccessToken}`,
      },
    })
    .reply(500, "Token not yet valid");
});
