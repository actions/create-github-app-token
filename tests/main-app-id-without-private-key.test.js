import { DEFAULT_ENV } from "./main.js";

for (const [key, value] of Object.entries({
  ...DEFAULT_ENV,
  "INPUT_CLIENT-ID": "",
  "INPUT_APP-ID": "123456",
  "INPUT_PRIVATE-KEY": "",
  ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token",
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runner-token",
})) {
  process.env[key] = value;
}

const _error = console.error;
console.error = (err) => _error(err?.message ?? err);

// Verify the deprecated `app-id` input is rejected for OIDC authentication.
const { default: promise } = await import("../main.js");
await promise;
process.exitCode = 0;
