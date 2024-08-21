import { test } from "./main.js";

await test((mockPool) => {
    process.env.INPUT_OWNER = process.env.GITHUB_REPOSITORY_OWNER;
    process.env.INPUT_REPOSITORIES = process.env.GITHUB_REPOSITORY;
    const mockInstallationId = "123456";
  
    mockPool
      .intercept({
        path: `/app/installations/${mockInstallationId}/access_tokens`,
        method: "POST",
        headers: {
          accept: "application/vnd.github.v3+json",
          "user-agent": "lepadatu-org/create-github-app-token-aws",
        //   Intentionally omitting the `authorization` header.
        },
      })
      .reply(403, "Forbidden");
    }
)
