import { test } from "./main.js";

// Verify `main` accepts a GitHub App client ID via the `app-id` input
await test(() => {
  process.env["INPUT_APP-ID"] = "Iv1.0123456789abcdef";
});
