import { OIDC_ENV, startOidcServer } from "./main.js";

for (const [key, value] of Object.entries(OIDC_ENV)) {
  process.env[key] = value;
}

const _error = console.error;
console.error = (err) => _error(err?.message ?? err);

// Verify `main` exits with an error when the OIDC token request fails.
const oidcServer = await startOidcServer({ status: 403 });
const { default: promise } = await import("../main.js");
await promise;
await oidcServer.close();
process.exitCode = 0;
