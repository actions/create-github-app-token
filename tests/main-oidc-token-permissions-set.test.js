import { OIDC_ENV, test } from "./main.js";

// Verify `main` authenticates with an OIDC token when `private-key` isn’t set, and that the
// OIDC audience falls back to https://github.com when `GITHUB_SERVER_URL` isn’t set.
await test(() => {
  delete process.env.GITHUB_SERVER_URL;
  process.env["INPUT_PERMISSION-ISSUES"] = "write";
}, OIDC_ENV);
