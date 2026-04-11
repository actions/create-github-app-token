import { DEFAULT_ENV, test } from "./main.js";

// Verify `main` falls back to `app-id` when `client-id` is not set
await test(
  () => {},
  {
    ...DEFAULT_ENV,
    "INPUT_CLIENT-ID": "",
    "INPUT_APP-ID": "123456",
  }
);
