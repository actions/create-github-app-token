// Verify `main` creates a token when the `owner` input is set and the `repositories` input is set (specifically, to multiple repos).
// @ts-check

import { test } from "./main.js";

await test(() => {
  process.env.INPUT_REPOSITORIES = `${process.env.GITHUB_REPOSITORY},actions/toolkit`;
});
