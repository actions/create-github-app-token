// Verify `main` creates a token when the `owner` input is not set but the `repositories` input is set.
// @ts-check
import { test } from "./main.js";

await test(() => {
  delete process.env.INPUT_OWNER;
});
