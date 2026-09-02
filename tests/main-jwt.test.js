import { DEFAULT_ENV, test } from "./main.js";

// Verify `main` creates a token from a caller-supplied JWT
await test(() => {}, {
  ...DEFAULT_ENV,
  "INPUT_PRIVATE-KEY": "",
  INPUT_JWT:
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTcwMDAwMDYwMCwiaXNzIjoiSXYxLjAxMjM0NTY3ODlhYmNkZWYifQ.signature",
});
