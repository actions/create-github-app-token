import { test, DEFAULT_ENV } from "./main.js";

// Verify that main works with a custom GitHub API URL passed as `github-api-url` input
await test(
  () => {
    process.env.INPUT_OWNER = process.env.GITHUB_REPOSITORY_OWNER;
    process.env.INPUT_REPOSITORIES = process.env.GITHUB_REPOSITORY;
  },
  {
    ...DEFAULT_ENV,
    "INPUT_GITHUB-API-URL": "https://github.acme-inc.com/api/v3",
  }
);
