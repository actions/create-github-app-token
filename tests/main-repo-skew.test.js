import { mock } from "node:test";

import { test } from "./main.js";

// Verify `main` retry when the clock has drifted.
await test((mockPool) => {
  process.env.INPUT_OWNER = "actions";
  process.env.INPUT_REPOSITORIES = "failed-repo";
  const owner = process.env.INPUT_OWNER;
  const repo = process.env.INPUT_REPOSITORIES;
  const mockInstallationId = "123456";
  const mockAppSlug = "github-actions";

  mock.timers.enable({ apis: ["Date"], now: 0 });

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
    .reply(({ headers }) => {
      const [_, jwt] = (headers.authorization || "").split(" ");
      const payload = JSON.parse(
        Buffer.from(jwt.split(".")[1], "base64").toString(),
      );

      if (payload.iat < 0) {
        return {
          statusCode: 401,
          data: {
            message:
              "'Issued at' claim ('iat') must be an Integer representing the time that the assertion was issued.",
          },
          responseOptions: {
            headers: {
              "content-type": "application/json",
              date: new Date(Date.now() + 30000).toUTCString(),
            },
          },
        };
      }

      return {
        statusCode: 200,
        data: {
          id: mockInstallationId,
          app_slug: mockAppSlug,
        },
        responseOptions: {
          headers: {
            "content-type": "application/json",
          },
        },
      };
    })
    .times(2);
}).finally(() => {
  mock.timers.reset();
});
