// @ts-check
import { test } from "./main.js";

// Verify `main` successfully obtains a token when the `owner` and `repositories` inputs are set (and the latter is a single repo).
await test();
