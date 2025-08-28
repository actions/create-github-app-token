import { DEFAULT_ENV } from "./main.js";

// Verify `main` exits with an error when `enterprise-slug` is used with both `owner` and `repositories` inputs.
try {
  // Set up environment with enterprise-slug, owner, and repositories all set
  for (const [key, value] of Object.entries(DEFAULT_ENV)) {
    process.env[key] = value;
  }
  process.env["INPUT_ENTERPRISE-SLUG"] = "test-enterprise";
  process.env.INPUT_OWNER = "test-owner";
  process.env.INPUT_REPOSITORIES = "repo1,repo2";
  
  await import("../main.js");
} catch (error) {
  console.error(error.message);
}
