import { test } from "./main.js";

// Verify `main` successfully sets permissions
await test(() => {
  process.env["INPUT_PERMISSION-ISSUES"] = `write`;
  process.env["INPUT_PERMISSION-PULL-REQUESTS"] = `read`;
});
