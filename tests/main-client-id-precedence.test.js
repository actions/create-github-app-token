import { DEFAULT_ENV, test } from "./main.js";

// Verify `client-id` takes precedence when both `client-id` and `app-id` are set
await test(
  () => {},
  {
    ...DEFAULT_ENV,
    "INPUT_CLIENT-ID": "Iv1.0123456789abcdef",
    "INPUT_APP-ID": "123456",
  }
);
