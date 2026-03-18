import { DEFAULT_ENV } from "./main.js";

for (const [key, value] of Object.entries({
  ...DEFAULT_ENV,
  "INPUT_CLIENT-ID": "",
  "INPUT_APP-ID": "",
})) {
  process.env[key] = value;
}

// Verify `main` exits with an error when neither `client-id` nor `app-id` is set.
const { default: promise } = await import("../main.js");
await promise;
process.exitCode = 0;
