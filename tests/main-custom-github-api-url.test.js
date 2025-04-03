import { DEFAULT_ENV, test } from "./main.js";

// Verify that main works with a custom GitHub API URL passed as `github-api-url` input
await test(
  () => {
    process.env.INPUT_OWNER = process.env.GITHUB_REPOSITORY_OWNER;
    const currentRepoName = process.env.GITHUB_REPOSITORY.split("/")[1];
    process.env.INPUT_REPOSITORIES = currentRepoName;
  },
  {
    ...DEFAULT_ENV,
    "INPUT_GITHUB-API-URL": "https://github.acme-inc.com/api/v3",
  }
);
