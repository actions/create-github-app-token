import { test, DEFAULT_ENV } from "./main.js";

// Verify `main` successfully obtains a token when the `owner` input is not set, but the `repositories` input is set.
await test(() => {
  process.env['INPUT_PRIVATE-KEY'] = DEFAULT_ENV.PRIVATE_KEY.replace(/\n/g, '\\n')
});
