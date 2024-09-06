import { test } from "./main.js";

// Verify `main` successfully obtains a token when the `owner` input is not set, but the `repositories` input is set.
await test(() => {
  delete process.env.INPUT_OWNER;
  const currentRepoName = process.env.GITHUB_REPOSITORY.split("/")[1];
  process.env.INPUT_REPOSITORIES = currentRepoName;
});
