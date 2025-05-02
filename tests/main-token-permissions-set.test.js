import { test } from "./main.js";

// Verify `main` successfully sets permissions
await test(() => {
  process.env["INPUT_PERMISSION_ISSUES"] = `write`;
  process.env["INPUT_PERMISSION_PULL_REQUESTS"] = `read`;
});
