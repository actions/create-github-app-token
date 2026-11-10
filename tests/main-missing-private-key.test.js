import { DEFAULT_ENV } from "./main.js";

for (const [key, value] of Object.entries({
  ...DEFAULT_ENV,
  "INPUT_PRIVATE-KEY": "",
})) {
  process.env[key] = value;
}

// Log only the error message, not the full stack trace, because the stack
// trace contains environment-specific paths and ANSI codes that differ
// between local and CI environments.
const _error = console.error;
console.error = (err) => _error(err?.message ?? err);

delete process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;

// Verify missing private-key and OIDC permissions produce an actionable error.
const { default: promise } = await import("../main.js");
await promise;
process.exitCode = 0;
