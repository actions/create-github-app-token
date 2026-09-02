import { DEFAULT_ENV } from "./main.js";

for (const [key, value] of Object.entries({
  ...DEFAULT_ENV,
  "INPUT_PRIVATE-KEY": "",
  // Decodes to `{"iat":1700000000,"iss":"Iv1.0123456789abcdef"}`, without an `exp` claim.
  INPUT_JWT:
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDAwMDAwMDAsImlzcyI6Ikl2MS4wMTIzNDU2Nzg5YWJjZGVmIn0.signature",
})) {
  process.env[key] = value;
}

// Log only the error message, not the full stack trace, because the stack
// trace contains environment-specific paths and ANSI codes that differ
// between local and CI environments.
const _error = console.error;
console.error = (err) => _error(err?.message ?? err);

// Verify `main` exits with an error when `jwt` has no `exp` claim.
const { default: promise } = await import("../main.js");
await promise;
process.exitCode = 0;
