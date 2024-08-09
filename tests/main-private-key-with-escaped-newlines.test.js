import { DEFAULT_ENV, test } from "./main.js";

// Verify `main` works correctly when `private-key` input has escaped newlines
await test(() => {
  process.env['INPUT_PRIVATE-KEY'] = DEFAULT_ENV.PRIVATE_KEY.replace(/\n/g, '\\n')
});