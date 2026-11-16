import { OIDC_ENV } from "./main.js";

for (const [key, value] of Object.entries({
  ...OIDC_ENV,
  ACTIONS_ID_TOKEN_REQUEST_URL: "https://oidc.example/token",
  INPUT_ENTERPRISE: "test-enterprise",
})) {
  process.env[key] = value;
}

const _error = console.error;
console.error = (err) => _error(err?.message ?? err);

// Verify `main` exits with an error when OIDC authentication is used with the `enterprise` input.
const { default: promise } = await import("../main.js");
await promise;
process.exitCode = 0;
