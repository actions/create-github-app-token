import { DEFAULT_ENV, test } from "./main.js";

await test(() => {}, {
  ...DEFAULT_ENV,
  "INPUT_PERMISSIONS": "contents: read,pull-requests: write",
});