import { DEFAULT_ENV, test } from "./main.js";

// Verify `main` normalizes full repository names before installation lookup and token scoping.
await test(
  () => {},
  {
    ...DEFAULT_ENV,
    INPUT_OWNER: DEFAULT_ENV.GITHUB_REPOSITORY_OWNER,
    INPUT_REPOSITORIES: `${DEFAULT_ENV.GITHUB_REPOSITORY_OWNER}/toolkit,checkout`,
  },
);

