import { DEFAULT_ENV, test } from "./main.js";

// Verify `main` accepts a GitHub App client ID via the `client-id` input
await test(
  () => {},
  {
    ...DEFAULT_ENV,
    "INPUT_CLIENT-ID": "Iv1.0123456789abcdef",
    "INPUT_APP-ID": "",
  }
);
